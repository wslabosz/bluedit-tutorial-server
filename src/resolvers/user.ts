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
} from 'type-graphql'
import argon2 from 'argon2'
import { EntityManager } from '@mikro-orm/postgresql'
import { COOKIE_NAME, FORGET_PASSWORD_PREFIX } from '../constants'
import { UsernamePasswordInput } from './UsernamePasswordInput'
import { validateRegister } from '../utils/validateRegister'
import { sendEmail } from '../utils/sendEmail'
import { v4 } from 'uuid'

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

@Resolver()
export class UserResolver {
   @Query(() => User, { nullable: true })
   async me(@Ctx() { req, em }: MyContext) {
      // user not logged in
      if (!req.session.userId) {
         return null
      }
      const user = await em.findOne(User, { id: req.session.userId })
      return user
   }

   @Mutation(() => UserResponse)
   async register(
      @Arg('options') options: UsernamePasswordInput,
      @Ctx() { req, em }: MyContext
   ): Promise<UserResponse> {
      const errors = validateRegister(options)
      if (errors) {
         return { errors }
      }
      const hashedPassword = await argon2.hash(options.password)
      let user
      try {
         const result = await (em as EntityManager)
            .createQueryBuilder(User)
            .getKnexQuery()
            .insert({
               username: options.username,
               password: hashedPassword,
               email: options.email,
               created_at: new Date(),
               updated_at: new Date(),
            })
            .returning('*')
         user = result[0]
      } catch (err) {
         // duplicate username error code
         if (err.code === '23505') {
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
      @Ctx() { em, req }: MyContext
   ): Promise<UserResponse> {
      const user = await em.findOne(
         User,
         usernameOrEmail.includes('@')
            ? { email: usernameOrEmail }
            : { username: usernameOrEmail }
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
      @Ctx() { em, redis }: MyContext
   ) {
      const user = await em.findOne(User, { email })
      if (!user) {
         // the email is not in db
         return true
      }

      const token = v4()
      await redis.set(
         FORGET_PASSWORD_PREFIX + token,
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
      @Ctx() { em, redis, req }: MyContext
   ): Promise<UserResponse> {
      // TODO: extract this logic from validateRegister
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
      const userId = await redis.get(FORGET_PASSWORD_PREFIX + token)
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
      const user = await em.findOne(User, { id: parseInt(userId) })

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
      user.password = await argon2.hash(newPassword)
      await em.persistAndFlush(user)

      // log in user after change password
      req.session.userId = user.id

      return { user }
   }
}
