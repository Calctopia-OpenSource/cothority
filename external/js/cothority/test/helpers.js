"use strict";

const identity = require("../lib");
const fs = require("fs");
const child_process = require("child_process");

/**
 * generate a roster out of the given group and list of keypairs generated by
 * keypairs()
 *
 * @param {kyber.Group} group
 * @param {Object} keypairs keypairs object generated by the keypairs() function
 * @returns {cothority.Roster} the roster representing the list of keypairs
 */
function roster(group, keypairs) {
  const identities = [];
  const n = keypairs.length;
  for (var i = 0; i < n; i++) {
    const pub = keypairs[i].pub;
    const addr = "tcp://127.0.0.1:700" + i * 2;
    identities[i] = new identity.ServerIdentity(group, pub, addr);
  }
  return new identity.Roster(identities);
}

/**
 * keypairs returns n keypairs generated randomly from the given group
 *
 * @param {kyber.Group} group the group the keys belong to
 * @param {number} n the number of keypairs
 * @returns {Object} object keypairs with priv and pub fields
 */
function keypairs(group, n) {
  return Array.from(new Array(n), (val, index) => keypair(group));
}

/**
 * keypair return a random keypair from the given grou
 *
 * @param {kyber.Group} group the group the keys belong to
 * @returns {Object} object with keys "priv" for the private key and "pub" for
 * the public key
 */
function keypair(group) {
  const key = group.scalar().pick();
  const pub = group.point().mul(key);
  return {
    priv: key,
    pub: pub
  };
}

var spawned_conodes;

/**
 * killGolang kills the process ran by runGolang. It is recommended to put it at
 * the end of a test such as
 * ```
 *   after(function() {
 *       helpers.killGolang()
 *   });
 * ```
 *
 */
function killGolang() {
  spawned_conodes.kill();
  spawned_conodes.stdout.destroy();
  spawned_conodes.stderr.destroy();
  //child_process.execSync("pkill go");
}

/**
 * runGolang runs the main.go file that resides in the given directory with the
 * given arguments. It returns ta promise that resolves when the script outputs
 * OK. It's meant as a signal saying the conodes are running and listening.
 * The process MUST be kill at the end of the test using `killGolang`.
 *
 * @param {string} buildPath build directory
 * @param {Array} args to give to the script, as an array
 * @return {Promise} Promise that returns the data output by the golang script.
 */
function runGolang(buildPath, scriptArgs) {
  const spawn = child_process.spawn;
  return new Promise(function(resolve, reject) {
    console.log("build path = " + buildPath);
    const args = ["run", "main.go"];
    if (scriptArgs) args.concat(args);
    spawned_conodes = spawn("go", args, {
      cwd: buildPath,
      env: process.env,
      detached: true
    });
    spawned_conodes.unref();
    console.log("Conode PID: " + spawned_conodes.pid);
    spawned_conodes.on("error", err => {
      console.log("Errrrrooorrrr: " + err);
      throw err;
    });
    spawned_conodes.stdout.setEncoding("utf8");
    spawned_conodes.stdout.on("data", data => {
      resolve(data);
    });
    spawned_conodes.stderr.on("data", data => {
      console.log("error launching golang: " + data);
    });
    spawned_conodes.on("exit", (code, signal) => {
      console.log("exiting program: code" + code + " / signal " + signal);
    });
  });
}

/**
 * readSKipchainInfo reads the public.toml and genesis.txt file from the build
 * directory and returns a tuple [roster,genesisID]
 *
 * @param {string} build_dir the build directory where to find the files
 * @returns {Array} [roster,genesisID] : roster as `cothority.Roster` and
 * genesisID as a hexadecimal string
 */
function readSkipchainInfo(build_dir) {
  // read roster and genesis
  const group_file = build_dir + "/public.toml";
  const genesis_file = build_dir + "/genesis.txt";

  const groupToml = fs.readFileSync(group_file, "utf8");
  const genesisID = fs.readFileSync(genesis_file, "utf8");
  const roster = identity.Roster.fromTOML(groupToml);
  return [roster, genesisID];
}

module.exports = {
  keypair,
  keypairs,
  roster,
  runGolang,
  killGolang,
  readSkipchainInfo
};
