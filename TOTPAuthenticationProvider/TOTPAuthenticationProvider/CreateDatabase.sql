USE [master]
GO

/****** Object:  Database [TOTPAuthentication]    Script Date: 10/26/2014 10:50:15 AM ******/
CREATE DATABASE [TOTPAuthentication]
 CONTAINMENT = NONE
 ON  PRIMARY 
( NAME = N'TOTPAuthentication', FILENAME = N'https://storageaccount.blob.core.windows.net/container/TOTPAuthentication.mdf' , SIZE = 1048576KB , MAXSIZE = UNLIMITED, FILEGROWTH = 1024KB )
 LOG ON 
( NAME = N'TOTPAuthentication_log', FILENAME = N'https://storageaccount.blob.core.windows.net/container/TOTPAuthentication_log.ldf' , SIZE = 1048576KB , MAXSIZE = 1073741824KB , FILEGROWTH = 10%)
GO

USE [TOTPAuthentication]
GO

CREATE TABLE [dbo].[Secrets](
	[upn] [varchar](255) NOT NULL,
	[secret] [varchar](512) NOT NULL,
	[attempts] [int] NOT NULL,
	[lockedUntil] [datetime] NULL,
 CONSTRAINT [PK_Secrets] PRIMARY KEY CLUSTERED 
(
	[upn] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON)
)

GO

CREATE TABLE [dbo].[UsedCodes](
	[upn] [varchar](255) NOT NULL,
	[interval] [bigint] NOT NULL
) ON [PRIMARY]

GO