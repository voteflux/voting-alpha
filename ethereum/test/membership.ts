const Membership = artifacts.require("Membership")

contract("Add member", async ([a1, a2, a3]) => {
    console.log("Address1", a1)

    it("should add a member with some weight and timestamps", async () => {
        let membership = await Membership.deployed();
        let {weight, startTime, endTime} = await membership.getMember.call(a1);

        assert.equal(weight, 0);
        assert.equal(startTime, 0);
        assert.equal(endTime, 0);

        await membership.setMember(a1, 1337, 1, 2000000000);
        ({weight, startTime, endTime} = await membership.getMember.call(a1));

        assert.equal(weight, 1337);
        assert.equal(startTime, 1);
        assert.equal(endTime, 2000000000);
    })

    it("should allow adding and revoking admin status", async () => {
        let membership = await Membership.deployed();
        assert.equal(await membership.isAdmin.call(a2), false, 'admin check before grant');

        await membership.addAdmin(a2, {from: a1});
        assert.equal(await membership.isAdmin.call(a2), true, 'admin check post grant');

        await membership.revokeAdminSelf({from: a1})
        assert.equal(await membership.isAdmin.call(a1), false, 'admin check post grant');

        try {
            await membership.addAdmin(a3, {from: a3});
            throw new Error("addAdmin succeeded from bad address!")
        } catch (e) {
            assert.equal(e.reason, "NOT_ADMIN", "failed addAdmin from bad addr check")
        }
    })
});

