CREATE TABLE [dbo].[Users] (
    [Username] TEXT   NOT NULL,
    [Password] TEXT   NOT NULL,
    [Id]       BIGINT IDENTITY NOT NULL,
    [Privilege] SMALLINT NOT NULL DEFAULT 0, 
    PRIMARY KEY CLUSTERED ([Id] ASC)
);
