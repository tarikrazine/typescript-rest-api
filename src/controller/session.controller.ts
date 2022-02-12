import { Request, Response } from 'express';
import config from 'config';

import {
  createUserSession,
  updateUserSession,
  getUserSession,
} from '../service/session.service';
import { validatePassword } from '../service/user.service';
import { signJWT } from '../utils/jwt.utils';
import { CreateSessionInput } from '../schema/session.schema';

export const createUserSessionHandler = async (
  request: Request<{}, {}, CreateSessionInput['body']>,
  response: Response
) => {
  // Validate the User's password
  const user = await validatePassword(request.body);

  if (!user) {
    return response.status(401).send('Invalid email or password');
  }

  // Create Session
  const session = await createUserSession(
    user._id,
    request.get('user-agent') || ''
  );

  // Create an access token

  const accessToken = signJWT(
    {
      ...user,
      session: session._id,
    },
    {
      expiresIn: config.get<string>('accessTokenTTL'), // 15 minutes
    }
  );

  // Create a refresh token
  const refreshToken = signJWT(
    {
      ...user,
      session: session._id,
    },
    {
      expiresIn: config.get<string>('refreshTokenTTL'), // 1 Year
    }
  );

  // Return access and refresh token
  return response.send({ accessToken, refreshToken });
};

export const getUserSessionHandler = async (
  request: Request,
  response: Response
) => {
  const user = response.locals.user;

  const sessions = await getUserSession({ user: user._id, valid: true });

  return response.send(sessions);
};

export const deleteUserSessionHandler = async (
  request: Request,
  response: Response
) => {
  const user = response.locals.user;

  await updateUserSession({ _id: user.session }, { valid: false });

  return response.send({
    accessToken: null,
    refreshToken: null,
  });
};
