import * as Knex from 'knex';
import { Account, AccountService } from '..';

console.log('here1');

const db = Knex({
    "debug": true,
    "useNullAsDefault": true,
    "dialect": "sqlite3",
    "connection": {
        "filename": ":memory:"
    }
});

describe('AccountService', () => {
    it('should create a new instance', () => {
        expect(true).toBe(true);
        expect(new AccountService(db)).toBeDefined();
    });
});

