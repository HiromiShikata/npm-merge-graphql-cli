import fs from 'fs';
import path from 'path';

const isVersionAtLeast = (version: string, minimum: number[]): boolean => {
  const actual = version.split('.').map(Number);
  return (
    actual[0] > minimum[0] ||
    (actual[0] === minimum[0] &&
      (actual[1] > minimum[1] ||
        (actual[1] === minimum[1] && actual[2] >= minimum[2])))
  );
};

describe('dependency security', () => {
  it('keeps the transitive handlebars dependency at or above the version fixing GHSA-8r5x-fm3f-whwj / GHSA-xw65-4hp5-5hc7 (JavaScript injection vulnerabilities)', () => {
    const lockFileContent = fs.readFileSync(
      path.join(__dirname, 'package-lock.json'),
      'utf8',
    );
    const parsed = JSON.parse(lockFileContent);
    const handlebarsVersion: string =
      parsed.packages['node_modules/handlebars'].version;

    expect(isVersionAtLeast(handlebarsVersion, [4, 7, 10])).toEqual(true);
  });

  it('pins the handlebars override in package.json at or above the version fixing GHSA-8r5x-fm3f-whwj / GHSA-xw65-4hp5-5hc7', () => {
    const packageJsonContent = fs.readFileSync(
      path.join(__dirname, 'package.json'),
      'utf8',
    );
    const parsed = JSON.parse(packageJsonContent);
    const handlebarsOverrideVersion: string | undefined =
      parsed.overrides && parsed.overrides.handlebars;

    expect(typeof handlebarsOverrideVersion).toEqual('string');
    expect(
      isVersionAtLeast(handlebarsOverrideVersion as string, [4, 7, 10]),
    ).toEqual(true);
  });
});
