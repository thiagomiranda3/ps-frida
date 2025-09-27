import { defineConfig } from "tsdown";

export default defineConfig({
	dts: true,
	entry: ["src/**/*.ts"],
	outDir: "built",
	unbundle: true,
});
