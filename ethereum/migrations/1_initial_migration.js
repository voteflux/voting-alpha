var Migrations = artifacts.require("./Migrations.sol");
var Membership = artifacts.require("./Membership.sol")

module.exports = function(deployer) {
  deployer.deploy(Migrations);
  deployer.deploy(Membership)
};
