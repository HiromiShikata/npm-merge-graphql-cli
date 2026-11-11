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

  it('keeps the bundled npm ip-address dependency at or above the version fixing GHSA-mwp4-54f8-5fhr (SSRF via octal octet parsing)', () => {
    const lockFileContent = fs.readFileSync(
      path.join(__dirname, 'package-lock.json'),
      'utf8',
    );
    const parsed = JSON.parse(lockFileContent);
    const ipAddressVersion: string =
      parsed.packages['node_modules/npm/node_modules/ip-address'].version;

    expect(isVersionAtLeast(ipAddressVersion, [10, 3, 1])).toEqual(true);
  });

  it('keeps the top-level undici dependency at or above the version fixing GHSA-w293-vg96-wgc3 (TLS certificate validation bypass in BalancedPool)', () => {
    const lockFileContent = fs.readFileSync(
      path.join(__dirname, 'package-lock.json'),
      'utf8',
    );
    const parsed = JSON.parse(lockFileContent);
    const undiciVersion: string =
      parsed.packages['node_modules/undici'].version;

    expect(isVersionAtLeast(undiciVersion, [7, 29, 1])).toEqual(true);
  });

  it('pins the npm override in package.json at or above the version bundling the patched ip-address and undici', () => {
    const packageJsonContent = fs.readFileSync(
      path.join(__dirname, 'package.json'),
      'utf8',
    );
    const parsed = JSON.parse(packageJsonContent);
    const npmOverrideVersion: string | undefined =
      parsed.overrides && parsed.overrides.npm;

    expect(typeof npmOverrideVersion).toEqual('string');
    expect(isVersionAtLeast(npmOverrideVersion as string, [11, 21, 0])).toEqual(
      true,
    );
  });
});

type MinimumVersionCase = {
  packageName: string;
  location: 'package.json devDependencies' | 'package-lock.json resolved';
  minimum: number[];
};

const exactVersionPattern = /^\d+\.\d+\.\d+$/;

const readDeclaredVersion = (testCase: MinimumVersionCase): string => {
  const parsed = JSON.parse(
    fs.readFileSync(
      path.join(
        __dirname,
        testCase.location === 'package.json devDependencies'
          ? 'package.json'
          : 'package-lock.json',
      ),
      'utf8',
    ),
  );
  return testCase.location === 'package.json devDependencies'
    ? parsed.devDependencies[testCase.packageName]
    : parsed.packages[`node_modules/${testCase.packageName}`].version;
};

describe('dependency refresh', () => {
  it('declares @swc/core as an exact version in package.json and resolves every refreshed dependency at or above its target version in package-lock.json', () => {
    const cases: MinimumVersionCase[] = [
      {
        packageName: '@swc/core',
        location: 'package.json devDependencies',
        minimum: [1, 16, 18],
      },
      {
        packageName: '@swc/core',
        location: 'package-lock.json resolved',
        minimum: [1, 16, 18],
      },
      {
        packageName: 'conventional-changelog-conventionalcommits',
        location: 'package-lock.json resolved',
        minimum: [10, 4, 1],
      },
      {
        packageName: 'dotenv',
        location: 'package-lock.json resolved',
        minimum: [18, 0, 7],
      },
    ];

    const actual = cases.map((testCase) => {
      const version = readDeclaredVersion(testCase);
      return {
        packageName: testCase.packageName,
        location: testCase.location,
        meetsMinimum:
          exactVersionPattern.test(version) &&
          isVersionAtLeast(version, testCase.minimum),
      };
    });
    const expected = cases.map((testCase) => ({
      packageName: testCase.packageName,
      location: testCase.location,
      meetsMinimum: true,
    }));

    expect(actual).toEqual(expected);
  });
});

describe('undici and npm security patch', () => {
  it('resolves every undici copy in package-lock.json at or above the patched release for its major version', () => {
    const parsed = JSON.parse(
      fs.readFileSync(path.join(__dirname, 'package-lock.json'), 'utf8'),
    );
    const patchedMinimumByMajor: Record<number, number[]> = {
      6: [6, 29, 1],
      7: [7, 30, 1],
    };
    const undiciEntries = Object.keys(parsed.packages)
      .filter((lockfilePath) => lockfilePath.endsWith('node_modules/undici'))
      .map((lockfilePath) => {
        const version: string = parsed.packages[lockfilePath].version;
        const major = Number(version.split('.')[0]);
        const minimum = patchedMinimumByMajor[major] ?? [7, 30, 1];
        return {
          lockfilePath,
          version,
          patched: isVersionAtLeast(version, minimum),
        };
      });

    expect(undiciEntries.length).toBeGreaterThan(0);
    expect(undiciEntries).toEqual(
      undiciEntries.map((entry) => ({ ...entry, patched: true })),
    );
  });

  it('pins the npm override in package.json at or above 11.21.2, the first npm release bundling the patched undici 6.29.1', () => {
    const packageJsonContent = fs.readFileSync(
      path.join(__dirname, 'package.json'),
      'utf8',
    );
    const parsed = JSON.parse(packageJsonContent);
    const npmOverrideVersion: string | undefined = parsed.overrides?.npm;

    expect(typeof npmOverrideVersion).toEqual('string');
    expect(isVersionAtLeast(npmOverrideVersion as string, [11, 21, 2])).toEqual(
      true,
    );
  });
});
