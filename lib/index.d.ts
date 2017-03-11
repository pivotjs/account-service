/// <reference types="bluebird" />
import * as Knex from 'knex';
import * as Promise from 'bluebird';
export declare const Errors: {
    signup: {
        EMAIL_IN_USE: string;
    };
    signin: {
        NOT_FOUND: string;
        NOT_VERIFIED: string;
        WRONG_PASSWORD: string;
    };
};
export interface Account {
    id: string;
    email: string;
    hashpass: string;
    verified_at: number;
    changed_email_at: number;
    created_at: number;
    updated_at: number;
}
export declare class AccountService {
    private db;
    constructor(db: Knex);
    initialize(): Promise<void>;
    signup(email: string, password: string): Promise<string>;
    verify(email: string): any;
    signin(email: string, password: string, options?: {
        isVerified: boolean;
    }): Promise<Account>;
    private createAccount(email, password);
}
