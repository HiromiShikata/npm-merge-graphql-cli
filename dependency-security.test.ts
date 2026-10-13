import fs from 'fs';
import path from 'path';

describe('dependency security', () => {
  it('keeps the transitive handlebars dependency at or above the version fixing GHSA-8r5x-fm3f-whwj / GHSA-xw65-4hp5-5hc7 (JavaScript injection vulnerabilities)', () => {
    const lockFileContent = fs.readFileSync(
      path.join(__dirname, 'package-lock.json'),
      'utf8',
    );
    const parsed = JSON.parse(lockFileContent);
    const handlebarsVersion: string =
      parsed.packages['node_modules/handlebars'].version;

    const actual = handlebarsVersion.split('.').map(Number);
    const minimumFixed = [4, 7, 10];

    const isAtLeastMinimumFixed =
      actual[0] > minimumFixed[0] ||
      (actual[0] === minimumFixed[0] &&
        (actual[1] > minimumFixed[1] ||
          (actual[1] === minimumFixed[1] && actual[2] >= minimumFixed[2])));

    expect(isAtLeastMinimumFixed).toEqual(true);
  });
});
