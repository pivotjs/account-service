export interface Account {
    id: string;
    name?: string;
    email: string;
    hashpass: string;
    verified_at?: Date;
    created_at: Date;
    updated_at: Date;
};

export interface Session {
    accountId: string;
}
