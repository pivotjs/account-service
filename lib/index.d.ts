/// <reference types="bluebird" />
import * as Knex from 'knex';
import * as Promise from 'bluebird';
export interface Account {
    id: string;
    name?: string;
    email: string;
    hashpass: string;
    verified_at?: number;
    created_at: number;
    updated_at: number;
}
export declare class AccountService {
    private db;
    constructor(db: Knex);
    initialize(): Promise<void>;
    signup(email: string, password: string): Promise<string>;
    verify(email: string): any;
    private createAccount(email, password);
}
