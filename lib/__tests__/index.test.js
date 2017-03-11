"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Knex = require("knex");
var bcrypt = require("bcrypt");
var __1 = require("..");
var db = Knex({
    "debug": false,
    "useNullAsDefault": true,
    "dialect": "sqlite3",
    "connection": {
        "filename": ":memory:"
    }
});
describe('AccountService', function () {
    it('should be possible to create an instance', function () {
        expect(new __1.AccountService(db)).toBeDefined();
    });
});
describe('AccountService.signup', function () {
    var service = new __1.AccountService(db);
    var account = {
        id: 'account-1',
        email: 'account-1@mailinator.com',
        hashpass: '123',
        created_at: new Date(),
        updated_at: new Date(),
    };
    beforeAll(function () {
        return service.initialize();
    });
    afterAll(db.destroy);
    beforeEach(function () {
        return db('account')
            .delete()
            .then(function () { return db('account').insert(account); });
    });
    describe('when the email is not in use', function () {
        it('should create a new account', function () {
            var email = 'account-2@mailinator.com';
            var password = '123';
            return service.signup(email, password).then(function (id) {
                expect(id).toBeDefined();
                return db('account')
                    .select('*')
                    .where('id', id)
                    .then(function (accounts) {
                    expect(accounts.length).toBe(1);
                    expect(accounts[0].email).toBe(email);
                    expect(bcrypt.compareSync(password, accounts[0].hashpass)).toBeTruthy();
                });
            });
        });
    });
    describe('when the email is already in use', function () {
        it('should not a new account', function () {
            var email = 'account-1@mailinator.com';
            var password = '123';
            return service.signup(email, password).catch(function (err) {
                expect(err).toBe('EMAIL_IN_USE');
            });
        });
    });
});
