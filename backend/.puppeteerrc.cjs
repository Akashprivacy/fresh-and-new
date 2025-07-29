const { join } = require('path');

/**
 * @type {import("puppeteer").Configuration}
 */
module.exports = {
  /**
   * Defines the directory where Puppeteer stores the browser downloads.
   * On Render, this is pointed to a persistent cache directory to avoid
   * re-downloading on every deploy and to fix the "Could not find Chrome" error.
   * For local development, it will use a standard '.cache/puppeteer' folder.
   */
  cacheDirectory: process.env.RENDER
    ? '/opt/render/.cache/puppeteer'
    : join(__dirname, '.cache', 'puppeteer'),
};