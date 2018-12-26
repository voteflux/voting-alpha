const Membership = artifacts.require("Membership")

contract("Add member", async ([a1]) => {
    console.log("Address1", a1)

    it("should add a member with some weight and timestamps", async () => {
        let membership = await Membership.deployed();
        console.log(membership.address);
        let {weight, startTime, endTime} = await membership.getMember.call(a1);

        assert.equal(weight, 0);
        assert.equal(startTime, 0);
        assert.equal(endTime, 0);

        const setMemberResult = await membership.setMember(a1, 1337, 1, 2000000000);
        ({weight, startTime, endTime} = await membership.getMember.call(a1));

        assert.equal(weight, 1337);
        assert.equal(startTime, 1);
        assert.equal(endTime, 2000000000);
    })
});
