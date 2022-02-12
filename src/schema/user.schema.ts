import { object, string, TypeOf } from 'zod';

export const createUserInput = object({
  body: object({
    name: string({ required_error: 'Name is Required' }),
    email: string({ required_error: 'Email is Required' }).email(
      'Not a valid email'
    ),
    password: string({
      required_error: 'Password is required',
    }).min(6, 'Password too short - should be 6 chars minimum'),
    passwordConfirmation: string({
      required_error: 'Password confirmation is required',
    }),
  }).refine((data) => data.password === data.passwordConfirmation, {
    message: 'Passwords do not match',
    path: ['passwordConfirmation'],
  }),
});

export type CreateUserInput = Omit<
  TypeOf<typeof createUserInput>,
  'body.passwordConfirmation'
>;
