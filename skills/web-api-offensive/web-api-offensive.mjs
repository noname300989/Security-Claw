#!/usr/bin/env node
import { Command } from "commander";
import { runCommand } from "../../src/infra/exec.js";

const program = new Command();

program.name("web-api-offensive").description("Offensive security tool for Web and APIs");

program
  .command("scan")
  .description("Scan target using Nuclei")
  .argument("<target>", "Target URL or hostname")
  .option("-t, --templates <path>", "Path to Nuclei templates")
  .action(async (target, options) => {
    console.log(`[*] Starting Nuclei scan on ${target}...`);
    // In a real environment, this would call 'nuclei -u target'
    // For now, we simulate the output
    const cmd = `nuclei -u ${target} ${options.templates ? `-t ${options.templates}` : ""}`;
    console.log(`[EXEC] ${cmd}`);
  });

program
  .command("fuzz")
  .description("Fuzz endpoints using ffuf")
  .argument("<url>", "Target URL with FUZZ keyword")
  .argument("<wordlist>", "Path to wordlist")
  .action(async (url, wordlist) => {
    console.log(`[*] Starting ffuf on ${url}...`);
    const cmd = `ffuf -u ${url} -w ${wordlist}`;
    console.log(`[EXEC] ${cmd}`);
  });

program.parse();
