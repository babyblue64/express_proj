import {Request, Response} from 'express';
import { prismaClient } from '..';
import { hashSync, compareSync } from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { JWT_SECRET } from '../secrets';

export const signup = async (req: Request, res: Response) => {
    const { email, password, name } = req.body;

    let user = await prismaClient.user.findFirst({ where: { email: email } });

    if (user) {
        throw Error('User already exists!');
    };

    user = await prismaClient.user.create({
        data: {
            name: name,
            email: email,
            password: hashSync(password, 10)
        },
    });
    res.json(user);
};

export const login = async (req: Request, res: Response) => {
    const { email, password } = req.body;

    let user = await prismaClient.user.findFirst({ where: { email: email } });

    if (!user) {
        throw Error('User not registered');
    };

    if (!compareSync(password, user.password)) {
        throw Error('Incorrect password');
    };

    const token = jwt.sign({ 
        userId: user.id
    }, JWT_SECRET)

    res.json(token);
};