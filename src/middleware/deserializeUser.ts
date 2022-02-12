import { Request, Response, NextFunction } from 'express';
import { get } from 'lodash';

import { reIssueAccessToken } from '../service/session.service';
import { verifyJWT } from '../utils/jwt.utils';

const deserializeUser = async (
  request: Request,
  response: Response,
  next: NextFunction
) => {
  const accessToken = get(request, 'headers.authorization', '').replace(
    /^Bearer\s/,
    ''
  );

  const refreshToken = get(request, 'headers.x-refresh');

  if (!accessToken) {
    return next();
  }

  const { decoded, expired } = verifyJWT(accessToken);

  if (decoded) {
    response.locals.user = decoded;
    return next();
  }

  if (expired && refreshToken) {
    const newAccessToken = await reIssueAccessToken({ refreshToken });

    if (newAccessToken) {
      response.setHeader('x-access-token', newAccessToken);
    }

    const { decoded } = verifyJWT(newAccessToken as string);

    response.locals.user = decoded;
    return next();
  }

  return next();
};

export default deserializeUser;
