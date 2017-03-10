"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Knex = require("knex");
var __1 = require("..");
console.log('here1');
var db = Knex({
    "debug": true,
    "useNullAsDefault": true,
    "dialect": "sqlite3",
    "connection": {
        "filename": ":memory:"
    }
});
describe('AccountService', function () {
    it('should create a new instance', function () {
        expect(true).toBe(true);
        expect(new __1.AccountService(db)).toBeDefined();
    });
});
