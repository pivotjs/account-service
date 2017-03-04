CREATE TABLE account (
    id VARCHAR(14),
    name TEXT,
    email TEXT UNIQUE NOT NULL,
    hashpass TEXT NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,

    PRIMARY KEY (id)
);
