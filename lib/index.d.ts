/// <reference types="bluebird" />
import * as Knex from 'knex';
import * as Promise from 'bluebird';
export declare const Errors: {
    EMAIL_IN_USE: string;
    NOT_FOUND: string;
    NOT_VERIFIED: string;
    WRONG_PASSWORD: string;
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
        mustBeVerified: boolean;
    }): Promise<Account>;
    changeEmail(id: string, password: string, newEmail: string): any;
    changePassword(id: string, password: string, newPassword: string): void;
    requestResetPassword(email: string, expireAt: number): void;
    resetPassword(resetKey: string, newPassword: string): void;
    private createAccount(email, password);
    private findOne(attributes);
    private validatePassword(account, password);
    private validateIsVerified(account, mustBeVerified?);
}
