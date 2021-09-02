import { User } from '../entities/User'
import { MyContext } from 'src/types'
import {
   Arg,
   Ctx,
   Field,
   Resolver,
   Mutation,
   ObjectType,
   Query,
   FieldResolver,
   Root,
} from 'type-graphql'
import argon2 from 'argon2'
import { COOKIE_NAME, FORGOT_PASSWORD_PREFIX } from '../constants'
import { UsernamePasswordInput } from './UsernamePasswordInput'
import { validateRegister } from '../utils/validateRegister'
import { sendEmail } from '../utils/sendEmail'
import { v4 } from 'uuid'
import { getConnection } from 'typeorm'

@ObjectType()
class FieldError {
   @Field()
   field: string
   @Field()
   message: string
}

@ObjectType()
class UserResponse {
   @Field(() => [FieldError], { nullable: true })
   errors?: FieldError[]
   @Field(() => User, { nullable: true })
   user?: User
}

@Resolver(User)
export class UserResolver {
   @FieldResolver(() => String)
   email(@Root() user: User, @Ctx() { req }: MyContext) {
      // don't show email if it's not requesting user's
      if (req.session.userId === user.id) {
         return user.email
      }
      return ''
   }

   @Query(() => User, { nullable: true })
   me(@Ctx() { req }: MyContext) {
      // user not logged in
      if (!req.session.userId) {
         return null
      }
      return User.findOne(req.session.userId)
   }

   @Mutation(() => UserResponse)
   async register(
      @Arg('options') options: UsernamePasswordInput,
      @Ctx() { req }: MyContext
   ): Promise<UserResponse> {
      const errors = validateRegister(options)
      if (errors) {
         return { errors }
      }
      const hashedPassword = await argon2.hash(options.password)
      let user
      try {
         // User.create({}).save()
         const result = await getConnection()
            .createQueryBuilder()
            .insert()
            .into(User)
            .values({
               username: options.username,
               password: hashedPassword,
               email: options.email,
            })
            .returning('*')
            .execute()
         // userId
         user = result.raw[0]
      } catch (err) {
         // duplicate username error code
         if (err.code === '23505') {
            if (err.detail.includes('email')) {
               return {
                  errors: [
                     {
                        field: 'email',
                        message: 'email already exists',
                     },
                  ],
               }
            }
            return {
               errors: [
                  {
                     field: 'username',
                     message: 'username already taken',
                  },
               ],
            }
         }
      }
      // store user id session
      // this will set a cookie on the user
      // keep them logged in after registration
      req.session.userId = user.id

      return { user }
   }

   @Mutation(() => UserResponse)
   async login(
      @Arg('usernameOrEmail') usernameOrEmail: string,
      @Arg('password') password: string,
      @Ctx() { req }: MyContext
   ): Promise<UserResponse> {
      const user = await User.findOne(
         usernameOrEmail.includes('@')
            ? { where: { email: usernameOrEmail } }
            : { where: { username: usernameOrEmail } }
      )
      if (!user) {
         return {
            errors: [
               {
                  field: 'usernameOrEmail',
                  message: "user doesn't exist in database",
               },
            ],
         }
      }
      const valid = await argon2.verify(user.password, password)
      if (!valid) {
         return {
            errors: [
               {
                  field: 'password',
                  message: 'incorrect password',
               },
            ],
         }
      }

      req.session.userId = user.id

      return {
         user,
      }
   }

   @Mutation(() => Boolean)
   logout(@Ctx() { req, res }: MyContext) {
      return new Promise((resolve) =>
         req.session.destroy((err) => {
            res.clearCookie(COOKIE_NAME)
            if (err) {
               console.log(err)
               resolve(false)
               return
            }
            resolve(true)
         })
      )
   }

   @Mutation(() => Boolean)
   async forgotPassword(
      @Arg('email') email: string,
      @Ctx() { redis }: MyContext
   ) {
      const user = await User.findOne({ where: { email } })
      if (!user) {
         // the email is not in db
         return true
      }
      const token = v4()
      await redis.set(
         FORGOT_PASSWORD_PREFIX + token,
         user.id,
         'ex',
         1000 * 60 * 60 * 24
      ) // a day
      await sendEmail(
         email,
         `<a href="http://localhost:3000/change-password/${token}">reset password</a>`
      )
      return true
   }

   @Mutation(() => UserResponse)
   async changePassword(
      @Arg('token') token: string,
      @Arg('newPassword') newPassword: string,
      @Ctx() { redis, req }: MyContext
   ): Promise<UserResponse> {
      // TODO: extract this logic from validateRegister
      // TODO: add verification
      if (newPassword.length <= 5) {
         return {
            errors: [
               {
                  field: 'newPassword',
                  message: 'length must be greater than 5',
               },
            ],
         }
      }
      const key = FORGOT_PASSWORD_PREFIX + token
      const userId = await redis.get(key)
      if (!userId) {
         return {
            errors: [
               {
                  field: 'token',
                  message: 'token expired',
               },
            ],
         }
      }
      const userIdNum = parseInt(userId)
      const user = await User.findOne(userIdNum)

      if (!user) {
         return {
            errors: [
               {
                  field: 'token',
                  message: 'user no longer exists',
               },
            ],
         }
      }
      User.update(
         { id: userIdNum },
         {
            password: await argon2.hash(newPassword),
         }
      )
      await redis.del(key)

      // log in user after change password
      req.session.userId = user.id

      return { user }
   }
}
