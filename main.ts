import { App, Editor, MarkdownView, Menu, Modal, Notice, Plugin, PluginSettingTab, Setting } from "obsidian";
import { argon2id } from "hash-wasm";

const PREFIX = "ENC:v1:";
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const KDF_ITERATIONS = 3;
const KDF_MEMORY_KIB = 65_536;
const MASTER_KDF_SALT = new TextEncoder().encode("Markdown Password Vault / master key / v1");
const SECRET_KDF_INFO = new TextEncoder().encode("Markdown Password Vault / secret key / v1");

interface VaultSettings {
  autoLockMinutes: number;
  clipboardClearSeconds: number;
  algorithm: "aes-256-gcm";
  showActionIcons: boolean;
  defaultAction: "copy" | "show" | "menu";
}

const DEFAULT_SETTINGS: VaultSettings = {
  autoLockMinutes: 10,
  clipboardClearSeconds: 25,
  algorithm: "aes-256-gcm",
  showActionIcons: true,
  defaultAction: "menu"
};

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function isSecret(value: string): boolean {
  return /^ENC:v1:[A-Za-z0-9+/=]+$/.test(value.trim());
}

export default class MarkdownPasswordVaultPlugin extends Plugin {
  settings: VaultSettings = DEFAULT_SETTINGS;
  private key?: CryptoKey;
  private inactivityTimer?: number;
  private clearClipboardTimer?: number;

  async onload(): Promise<void> {
    this.settings = { ...DEFAULT_SETTINGS, ...(await this.loadData()) };
    this.addSettingTab(new VaultSettingTab(this.app, this));
    this.addCommand({ id: "unlock-vault", name: "Unlock vault", callback: () => this.openUnlockModal() });
    this.addCommand({ id: "lock-vault", name: "Lock vault", callback: () => this.lock() });
    this.addCommand({
      id: "encrypt-selection",
      name: "Encrypt selection",
      editorCallback: async (editor) => this.encryptSelection(editor)
    });
    this.addCommand({
      id: "insert-secret-template",
      name: "Insert secret template",
      editorCallback: (editor) => editor.replaceSelection("```secret\nlabel: \nusername: \npassword: \nurl: \nnotes: \n```")
    });

    this.registerEvent(this.app.workspace.on("editor-menu", (menu, editor) => this.addEditorActions(menu, editor)));
    this.registerMarkdownCodeBlockProcessor("secret", (source, el) => this.renderSecretBlock(source, el));
    this.registerMarkdownPostProcessor((el) => this.decorateSecrets(el));
    for (const event of ["mousemove", "keydown", "touchstart", "mousedown"] as const) {
      this.registerDomEvent(document, event, () => this.resetInactivityTimer(), { passive: true });
    }
    this.resetInactivityTimer();
  }

  onunload(): void { this.lock(false); }

  async saveSettings(): Promise<void> { await this.saveData(this.settings); this.resetInactivityTimer(); }

  isUnlocked(): boolean { return !!this.key; }

  async unlock(password: string): Promise<void> {
    if (!password) throw new Error("Master password cannot be empty.");
    this.zeroKeyMaterial();
    const passwordBytes = new TextEncoder().encode(password);
    try { this.key = await this.deriveMasterKey(passwordBytes); }
    finally { passwordBytes.fill(0); }
    this.resetInactivityTimer();
    new Notice("Vault unlocked. The key is held only in memory.");
  }

  lock(showNotice = true): void {
    window.clearTimeout(this.inactivityTimer);
    window.clearTimeout(this.clearClipboardTimer);
    this.zeroKeyMaterial();
    if (showNotice) new Notice("Vault locked.");
  }

  private zeroKeyMaterial(): void {
    this.key = undefined;
  }

  private resetInactivityTimer(): void {
    if (!this.isUnlocked()) return;
    window.clearTimeout(this.inactivityTimer);
    if (this.settings.autoLockMinutes > 0) {
      this.inactivityTimer = window.setTimeout(() => this.lock(), this.settings.autoLockMinutes * 60_000);
    }
  }

  private async deriveMasterKey(password: Uint8Array): Promise<CryptoKey> {
    const hash = await argon2id({ password, salt: MASTER_KDF_SALT, parallelism: 1, iterations: KDF_ITERATIONS, memorySize: KDF_MEMORY_KIB, hashLength: 32, outputType: "binary" });
    try { return await crypto.subtle.importKey("raw", asArrayBuffer(hash), "HKDF", false, ["deriveKey"]); }
    finally { hash.fill(0); }
  }

  private async secretKey(salt: Uint8Array): Promise<CryptoKey> {
    if (!this.key) throw new Error("Vault is locked.");
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: asArrayBuffer(salt), info: asArrayBuffer(SECRET_KDF_INFO) },
      this.key,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async encrypt(plainText: string): Promise<string> {
    if (!this.isUnlocked()) await this.openUnlockModal();
    if (!this.isUnlocked()) throw new Error("Unlock cancelled.");
    const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
    const key = await this.secretKey(salt);
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, new TextEncoder().encode(plainText)));
    const payload = new Uint8Array(salt.length + nonce.length + encrypted.length);
    payload.set(salt); payload.set(nonce, salt.length); payload.set(encrypted, salt.length + nonce.length);
    this.resetInactivityTimer();
    return PREFIX + bytesToBase64(payload);
  }

  async decrypt(secret: string): Promise<string> {
    if (!this.isUnlocked()) await this.openUnlockModal();
    if (!this.isUnlocked()) throw new Error("Unlock cancelled.");
    if (!isSecret(secret)) throw new Error("Invalid encrypted-secret format.");
    const payload = base64ToBytes(secret.trim().slice(PREFIX.length));
    if (payload.length <= SALT_BYTES + NONCE_BYTES + 16) throw new Error("Encrypted secret is too short.");
    const salt = payload.slice(0, SALT_BYTES);
    const nonce = payload.slice(SALT_BYTES, SALT_BYTES + NONCE_BYTES);
    const cipherText = payload.slice(SALT_BYTES + NONCE_BYTES);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, await this.secretKey(salt), cipherText);
    this.resetInactivityTimer();
    return new TextDecoder().decode(plain);
  }

  private async encryptSelection(editor: Editor): Promise<void> {
    const selection = editor.getSelection();
    if (!selection) return void new Notice("Select text to encrypt first.");
    try { editor.replaceSelection(await this.encrypt(selection)); new Notice("Selection encrypted."); }
    catch (error) { this.reportError(error); }
  }

  private addEditorActions(menu: Menu, editor: Editor): void {
    const value = editor.getLine(editor.getCursor().line).trim();
    if (!isSecret(value)) return;
    menu.addItem(item => item.setTitle("Copy decrypted secret").setIcon("copy").onClick(() => this.copySecret(value)));
    menu.addItem(item => item.setTitle("Show decrypted secret").setIcon("eye").onClick(() => this.showSecret(value)));
    menu.addItem(item => item.setTitle("Edit decrypted secret").setIcon("pencil").onClick(() => this.editSecret(editor, value)));
    menu.addItem(item => item.setTitle("Re-encrypt secret").setIcon("lock-keyhole").onClick(() => this.reencrypt(editor, value)));
  }

  private decorateSecrets(root: HTMLElement): void {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes: Text[] = [];
    let node: Node | null;
    while ((node = walker.nextNode())) {
      const parent = node.parentElement;
      if (parent && !parent.closest("button, code, pre, .mpv-secret-value") && node.textContent?.includes(PREFIX)) nodes.push(node as Text);
    }
    for (const textNode of nodes) {
      const text = textNode.textContent ?? "";
      const parts = text.split(/(ENC:v1:[A-Za-z0-9+/=]+)/g);
      if (parts.length < 3) continue;
      const fragment = document.createDocumentFragment();
      for (const part of parts) {
        if (!isSecret(part)) { fragment.appendText(part); continue; }
        const secret = document.createElement("span");
        secret.addClass("mpv-secret-value");
        secret.setText(PREFIX + "••••••••");
        secret.setAttribute("aria-label", "Encrypted secret; click for vault action");
        secret.addEventListener("click", event => {
          event.preventDefault(); event.stopPropagation();
          if (this.settings.defaultAction === "copy") void this.copySecret(part);
          else if (this.settings.defaultAction === "show") void this.showSecret(part);
          else this.openSecretMenu(part, event);
        });
        fragment.append(secret);
      }
      textNode.replaceWith(fragment);
    }
  }

  private openSecretMenu(secret: string, event: MouseEvent): void {
    const menu = new Menu();
    menu.addItem(item => item.setTitle("Copy decrypted secret").setIcon("copy").onClick(() => this.copySecret(secret)));
    menu.addItem(item => item.setTitle("Show decrypted secret").setIcon("eye").onClick(() => this.showSecret(secret)));
    menu.addItem(item => item.setTitle("Edit decrypted secret").setIcon("pencil").onClick(() => this.editActiveSecret(secret)));
    menu.addItem(item => item.setTitle("Re-encrypt secret").setIcon("lock-keyhole").onClick(() => this.reencryptActiveSecret(secret)));
    menu.showAtMouseEvent(event);
  }

  private activeEditor(): Editor | undefined {
    const view = this.app.workspace.getActiveViewOfType(MarkdownView);
    return view?.editor;
  }

  private async editActiveSecret(secret: string): Promise<void> {
    const editor = this.activeEditor();
    if (!editor) return void new Notice("Open this note in the Markdown editor to replace the secret.");
    try {
      new EditModal(this.app, await this.decrypt(secret), async value => {
        const source = editor.getValue();
        if (!source.includes(secret)) throw new Error("The encrypted value is no longer in the active note.");
        editor.setValue(source.replace(secret, await this.encrypt(value)));
      }).open();
    } catch (error) { this.reportError(error); }
  }

  private async reencryptActiveSecret(secret: string): Promise<void> {
    const editor = this.activeEditor();
    if (!editor) return void new Notice("Open this note in the Markdown editor to replace the secret.");
    try {
      const source = editor.getValue();
      if (!source.includes(secret)) throw new Error("The encrypted value is no longer in the active note.");
      editor.setValue(source.replace(secret, await this.encrypt(await this.decrypt(secret))));
      new Notice("Secret re-encrypted with a new salt and nonce.");
    } catch (error) { this.reportError(error); }
  }

  private async copySecret(secret: string): Promise<void> {
    try {
      const value = await this.decrypt(secret);
      await navigator.clipboard.writeText(value);
      window.clearTimeout(this.clearClipboardTimer);
      if (this.settings.clipboardClearSeconds > 0) this.clearClipboardTimer = window.setTimeout(() => navigator.clipboard.writeText(""), this.settings.clipboardClearSeconds * 1000);
      new Notice("Secret copied; clipboard will be cleared automatically.");
    } catch (error) { this.reportError(error); }
  }

  private async showSecret(secret: string): Promise<void> {
    try { new RevealModal(this.app, await this.decrypt(secret), 8_000).open(); }
    catch (error) { this.reportError(error); }
  }

  private async editSecret(editor: Editor, secret: string): Promise<void> {
    try { new EditModal(this.app, await this.decrypt(secret), async value => editor.replaceRange(await this.encrypt(value), editor.getCursor("from"), editor.getCursor("to"))).open(); }
    catch (error) { this.reportError(error); }
  }

  private async reencrypt(editor: Editor, secret: string): Promise<void> {
    try { editor.setLine(editor.getCursor().line, await this.encrypt(await this.decrypt(secret))); new Notice("Secret re-encrypted with a new salt and nonce."); }
    catch (error) { this.reportError(error); }
  }

  private async renderSecretBlock(source: string, el: HTMLElement): Promise<void> {
    el.addClass("mpv-secret-block");
    const secret = source.match(/^password:\s*(.+)$/m)?.[1]?.trim();
    if (!secret || !isSecret(secret)) { el.createEl("em", { text: "Encrypt the password value first, then preview this block." }); return; }
    el.createEl("strong", { text: source.match(/^label:\s*(.+)$/m)?.[1]?.trim() || "Secret" });
    const actions = el.createDiv({ cls: "mpv-secret-actions" });
    const add = (label: string, action: () => void) => actions.createEl("button", { text: label }).addEventListener("click", action);
    add("Copy", () => this.copySecret(secret)); add("Show", () => this.showSecret(secret));
  }

  private openUnlockModal(): Promise<void> { return new Promise(resolve => new UnlockModal(this.app, this, resolve).open()); }
  private reportError(error: unknown): void { new Notice(error instanceof Error ? error.message : "Vault operation failed."); }
}

class UnlockModal extends Modal {
  constructor(app: App, private plugin: MarkdownPasswordVaultPlugin, private done: () => void) { super(app); }
  onOpen(): void { let value = ""; this.contentEl.createEl("h2", { text: "Unlock Markdown Password Vault" }); new Setting(this.contentEl).setName("Master password").addText(text => text.inputEl.type = "password").addButton(button => button.setButtonText("Unlock").setCta().onClick(async () => { try { await this.plugin.unlock(value); this.close(); } catch (e) { new Notice(e instanceof Error ? e.message : "Unable to unlock."); } })).settingEl.querySelector("input")?.addEventListener("input", event => value = (event.target as HTMLInputElement).value); }
  onClose(): void { this.contentEl.empty(); this.done(); }
}

class RevealModal extends Modal {
  constructor(app: App, private value: string, private delay: number) { super(app); }
  onOpen(): void { this.contentEl.createEl("h2", { text: "Secret" }); const value = this.contentEl.createDiv({ cls: "mpv-revealed", text: this.value }); window.setTimeout(() => { value.setText("Hidden"); this.close(); }, this.delay); }
  onClose(): void { this.contentEl.empty(); }
}

class EditModal extends Modal {
  constructor(app: App, private value: string, private save: (value: string) => Promise<void>) { super(app); }
  onOpen(): void { this.contentEl.createEl("h2", { text: "Edit secret" }); let value = this.value; new Setting(this.contentEl).addTextArea(area => { area.setValue(value); area.onChange(v => value = v); }).addButton(button => button.setButtonText("Save encrypted value").setCta().onClick(async () => { await this.save(value); this.close(); })); }
  onClose(): void { this.contentEl.empty(); }
}

class VaultSettingTab extends PluginSettingTab {
  constructor(app: App, private plugin: MarkdownPasswordVaultPlugin) { super(app, plugin); }
  display(): void {
    const { containerEl } = this;
    containerEl.empty();
    containerEl.createEl("h2", { text: "Markdown Password Vault" });
    new Setting(containerEl).setName("Auto-lock (minutes)").setDesc("Set 0 to disable inactivity locking.").addText(t => t.setValue(String(this.plugin.settings.autoLockMinutes)).onChange(async v => { this.plugin.settings.autoLockMinutes = Math.max(0, Number(v) || 0); await this.plugin.saveSettings(); }));
    new Setting(containerEl).setName("Clear clipboard after (seconds)").setDesc("Set 0 to keep the copied value.").addText(t => t.setValue(String(this.plugin.settings.clipboardClearSeconds)).onChange(async v => { this.plugin.settings.clipboardClearSeconds = Math.max(0, Number(v) || 0); await this.plugin.saveSettings(); }));
    new Setting(containerEl).setName("Default action for a clicked secret").addDropdown(d => d.addOption("menu", "Show action menu").addOption("copy", "Copy decrypted value").addOption("show", "Show briefly").setValue(this.plugin.settings.defaultAction).onChange(async v => { this.plugin.settings.defaultAction = v as VaultSettings["defaultAction"]; await this.plugin.saveSettings(); }));
    new Setting(containerEl).setName("Show action icons").addToggle(t => t.setValue(this.plugin.settings.showActionIcons).onChange(async v => { this.plugin.settings.showActionIcons = v; await this.plugin.saveSettings(); }));
    new Setting(containerEl).setName("Encryption format").setDesc("Version v1 currently uses AES-256-GCM with Argon2id and HKDF; the format is embedded in each secret.").addDropdown(d => d.addOption("aes-256-gcm", "AES-256-GCM (v1)").setValue(this.plugin.settings.algorithm).setDisabled(true));
  }
}
