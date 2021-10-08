import { Post } from '../entities/Post'
import { Upvote } from '../entities/Upvote'
import {
   Arg,
   Ctx,
   Field,
   FieldResolver,
   InputType,
   Int,
   Mutation,
   ObjectType,
   Query,
   Resolver,
   Root,
   UseMiddleware,
} from 'type-graphql'
import { MyContext } from '../types'
import { isAuth } from '../middleware/isAuth'
import { getConnection } from 'typeorm'

@InputType()
class PostInput {
   @Field()
   title: string
   @Field()
   text: string
}

@ObjectType()
class PaginatedPosts {
   @Field(() => [Post])
   posts: Post[]
   @Field()
   hasMore: boolean
}

@Resolver(Post)
export class PostResolver {
   @FieldResolver(() => String)
   textSnippet(@Root() post: Post) {
      return post.text.slice(0, 50)
   }

   @Query(() => PaginatedPosts)
   async posts(
      @Arg('limit', () => Int) limit: number,
      @Arg('cursor', () => String, { nullable: true }) cursor: string | null,
      @Ctx() { req }: MyContext
   ): Promise<PaginatedPosts> {
      const realLimit = Math.min(50, limit)
      const realLimitPlusOne = realLimit + 1

      const replacements: any[] = [realLimitPlusOne]
      if (req.session.userId) {
         replacements.push(req.session.userId)
      }
      let cursorIndex = 3
      if (cursor) {
         replacements.push(new Date(parseInt(cursor)))
         cursorIndex = replacements.length
      }
      const posts = await getConnection().query(
         `
         select p.*,
         json_build_object(
            'id', u.id,
            'username', u.username,
            'email', u.email,
            'createdAt', u."createdAt",
            'updatedAt', u."updatedAt"
            ) "createdBy",
         ${
            req.session.userId
               ? '(select value from upvote where "userId" = $2 and "postId" = p.id) "voteStatus"'
               : 'null as "voteStatus"'
         }
         from post p
         inner join public.user u on u.id = p."creatorId"
         ${cursor ? `where p."createdAt" < $${cursorIndex}` : ''}
         order by p."createdAt" DESC
         limit $1
         `,
         replacements
      )
      console.log(posts)

      return {
         posts: posts.slice(0, realLimit),
         hasMore: posts.length === realLimitPlusOne,
      }
   }

   @Query(() => Post, { nullable: true })
   post(@Arg('id') id: number): Promise<Post | undefined> {
      return Post.findOne(id)
   }

   @Mutation(() => Post)
   @UseMiddleware(isAuth)
   async createPost(
      @Arg('input') input: PostInput,
      @Ctx() { req }: MyContext
   ): Promise<Post> {
      return Post.create({ ...input, creatorId: req.session.userId }).save()
   }

   @Mutation(() => Post)
   async updatePost(
      @Arg('id') id: number,
      @Arg('title', () => String, { nullable: true }) title: string
   ): Promise<Post | null> {
      const post = await Post.findOne(id)
      if (!post) {
         return null
      }
      if (typeof title !== 'undefined') {
         await Post.update({ id }, { title })
      }
      return post
   }

   @Mutation(() => Boolean)
   async deletePost(@Arg('id') id: number): Promise<Boolean> {
      await Post.delete(id)
      return true
   }

   @Mutation(() => Boolean)
   @UseMiddleware(isAuth)
   async vote(
      @Arg('postId', () => Int) postId: number,
      @Arg('value', () => Int) value: number,
      @Ctx() { req }: MyContext
   ) {
      const isUpvote = value !== -1
      const realValue = isUpvote ? 1 : -1
      const { userId } = req.session
      const upvote = await Upvote.findOne({
         where: { userId: userId, postId: postId },
      })
      console.log(upvote)

      // user has voted on the post already
      // and changing their vote
      if (upvote && upvote.value !== realValue) {
         await getConnection().transaction(async (tm) => {
            await tm.query(
               `
               update upvote
               set value = $1
               where "postId" = $2 and "userId" = $3
            `,
               [realValue, postId, userId]
            )
            await tm.query(
               `
               update post 
               set points = points + $1
               where id = $2
            `,
               [2 * realValue, postId]
            )
         })
      } else if (!upvote) {
         // has never voted before
         await getConnection().transaction(async (tm) => {
            await tm.query(
               `insert into upvote ("userId", "postId", value)
            values($1, $2, $3);
            `,
               [userId, postId, realValue]
            )

            await tm.query(
               `update post 
            set points = points + $1
            where id = $2
            `,
               [realValue, postId]
            )
         })
      }
      return true
   }
}
