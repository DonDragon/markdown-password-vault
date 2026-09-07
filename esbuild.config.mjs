import esbuild from "esbuild";

const production = process.argv[2] === "production";
const context = await esbuild.context({
  entryPoints: ["main.ts"],
  bundle: true,
  external: ["obsidian", "electron", "@codemirror/*"],
  format: "cjs",
  target: "es2022",
  sourcemap: production ? false : "inline",
  minify: production,
  outfile: "main.js",
  logLevel: "info"
});

if (production) await context.rebuild();
else await context.watch();
