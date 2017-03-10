/// <reference types="bluebird" />
import * as Knex from 'knex';
import * as Promise from 'bluebird';
export interface Account {
    id: string;
    name?: string;
    email: string;
    hashpass: string;
    verified_at?: Date;
    created_at: Date;
    updated_at: Date;
}
export declare class AccountService {
    private db;
    constructor(db: Knex);
    initialize(): Promise<void>;
    signup(email: string, password: string): Promise<Account>;
    private createAccount(email, password);
}
