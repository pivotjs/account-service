/// <reference types="bluebird" />
import * as Knex from 'knex';
import * as Promise from 'bluebird';
export declare const AuthenticationErrors: {
    EMAIL_IN_USE: string;
    EXPIRED_RESET_KEY: string;
    MAX_FAILED_ATTEMPTS_DELAY: string;
    NOT_FOUND: string;
    NOT_VERIFIED: string;
    WRONG_PASSWORD: string;
};
export interface UserAccount {
    id: string;
    email: string;
    hashpass: string;
    reset_key: string;
    failed_attempts: number;
    max_failed_attempts_at: number;
    verified_email_at: number;
    changed_email_at: number;
    reset_expire_at: number;
    created_at: number;
    updated_at: number;
}
export interface AuthenticationServiceOptions {
    requireVerifiedEmail: boolean;
    maxFailedAttempts: number;
    maxFailedAttemptsDelay: number;
}
export declare class AuthenticationService {
    private db;
    constructor(db: Knex);
    initialize(): Promise<void>;
    signup(email: string, password: string): Promise<string>;
    verifyEmail(email: string): Knex.QueryBuilder;
    signin(email: string, password: string, options: AuthenticationServiceOptions): Promise<UserAccount>;
    changeEmail(id: string, password: string, newEmail: string, options: AuthenticationServiceOptions): Promise<any>;
    changePassword(id: string, password: string, newPassword: string, options: AuthenticationServiceOptions): Promise<any>;
    generateResetKey(email: string, expireAt: number): Promise<string>;
    resetPassword(email: string, resetKey: string, newPassword: string, options: AuthenticationServiceOptions): Promise<any>;
    private createAccount(email, password);
    private updateAccount(id, fields);
    private findOne(fields);
    private ensureEmailNotInUse(email);
    private ensureVerifiedEmail(account);
    private ensureAfterFailedAttemptsDelay(account, options);
    private ensureSamePassword(account, password, options);
    private ensureValidResetKey(account);
}
