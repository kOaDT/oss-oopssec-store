#!/usr/bin/env node

import { createOssStore } from "../src/index.js";

const args = process.argv.slice(2);
const projectName = args[0];

createOssStore(projectName);
