import {
    pgTable,
    text,
    uuid,
    boolean,
    timestamp,
    integer,
    pgEnum,
} from 'drizzle-orm/pg-core';

// Enums
export const userRoleEnum = pgEnum('user_role', ['admin', 'moderator', 'farmer', 'user']);

// ─────────────────────────────────────────────
// USERS
// ─────────────────────────────────────────────
export const users = pgTable('users', {
    id: uuid('id').primaryKey().defaultRandom(),
    email: text('email').unique().notNull(),
    username: text('username').unique().notNull(),
    displayName: text('display_name').notNull(),
    passwordHash: text('password_hash').notNull(),
    photoURL: text('photo_url'),
    role: userRoleEnum('role').default('user').notNull(),
    region: text('region').default('').notNull(),
    isVerified: boolean('is_verified').default(false).notNull(),
    followers: text('followers').array().default([]).notNull(),
    following: text('following').array().default([]).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// ─────────────────────────────────────────────
// COMMUNITIES
// ─────────────────────────────────────────────
export const communities = pgTable('communities', {
    id: text('id').primaryKey(), // slug like "wheat", "rice"
    name: text('name').notNull(),
    description: text('description').notNull(),
    imageUrl: text('image_url').default(''),
    creatorId: uuid('creator_id').references(() => users.id, { onDelete: 'set null' }),
    creatorUsername: text('creator_username').notNull(),
    postCount: integer('post_count').default(0).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// ─────────────────────────────────────────────
// POSTS
// ─────────────────────────────────────────────
export const posts = pgTable('posts', {
    id: uuid('id').primaryKey().defaultRandom(),
    uid: uuid('uid').references(() => users.id, { onDelete: 'cascade' }).notNull(),
    author: text('author').notNull(),
    authorPhotoURL: text('author_photo_url').default(''),
    authorRole: userRoleEnum('author_role').default('user'),
    title: text('title').notNull(),
    text: text('text').notNull(),
    communityId: text('community_id').references(() => communities.id, { onDelete: 'cascade' }).notNull(),
    imageUrl: text('image_url').default(''),
    upvoteCount: integer('upvote_count').default(0).notNull(),
    downvoteCount: integer('downvote_count').default(0).notNull(),
    commentCount: integer('comment_count').default(0).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

// ─────────────────────────────────────────────
// COMMENTS
// ─────────────────────────────────────────────
export const comments = pgTable('comments', {
    id: uuid('id').primaryKey().defaultRandom(),
    postId: uuid('post_id').references(() => posts.id, { onDelete: 'cascade' }).notNull(),
    uid: uuid('uid').references(() => users.id, { onDelete: 'cascade' }).notNull(),
    author: text('author').notNull(),
    authorPhotoURL: text('author_photo_url').default(''),
    text: text('text').notNull(),
    parentId: uuid('parent_id'), // null = top-level comment
    replyCount: integer('reply_count').default(0).notNull(),
    upvoteCount: integer('upvote_count').default(0).notNull(),
    downvoteCount: integer('downvote_count').default(0).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// ─────────────────────────────────────────────
// VOTES (posts)
// ─────────────────────────────────────────────
export const postVotes = pgTable('post_votes', {
    id: uuid('id').primaryKey().defaultRandom(),
    postId: uuid('post_id').references(() => posts.id, { onDelete: 'cascade' }).notNull(),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
    vote: text('vote').notNull(), // 'up' | 'down'
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// ─────────────────────────────────────────────
// VOTES (comments)
// ─────────────────────────────────────────────
export const commentVotes = pgTable('comment_votes', {
    id: uuid('id').primaryKey().defaultRandom(),
    commentId: uuid('comment_id').references(() => comments.id, { onDelete: 'cascade' }).notNull(),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
    vote: text('vote').notNull(), // 'up' | 'down'
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// ─────────────────────────────────────────────
// PRODUCTS (Verified Marketplace)
// ─────────────────────────────────────────────
export const products = pgTable('products', {
    id: uuid('id').primaryKey().defaultRandom(),
    uid: uuid('uid').references(() => users.id, { onDelete: 'cascade' }).notNull(),
    sellerName: text('seller_name').notNull(),
    sellerPhotoURL: text('seller_photo_url').default(''),
    sellerRole: text('seller_role').default('farmer'),
    itemName: text('item_name').notNull(),
    description: text('description').notNull(),
    price: integer('price').notNull(), // in paise (₹ * 100) or just rupees
    unit: text('unit').default('kg'),
    imageUrl: text('image_url').default(''),
    location: text('location').default(''),
    category: text('category').default(''),
    stock: integer('stock').default(0),
    rating: integer('rating').default(0),
    isAvailable: boolean('is_available').default(true).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// ─────────────────────────────────────────────
// MARKETPLACE POSTS (Indirect / Community Market)
// ─────────────────────────────────────────────
export const marketplacePosts = pgTable('marketplace_posts', {
    id: uuid('id').primaryKey().defaultRandom(),
    uid: uuid('uid').references(() => users.id, { onDelete: 'cascade' }).notNull(),
    sellerName: text('seller_name').notNull(),
    sellerPhotoURL: text('seller_photo_url').default(''),
    itemName: text('item_name').notNull(),
    description: text('description').notNull(),
    price: integer('price').notNull(),
    unit: text('unit').default('kg'),
    imageUrl: text('image_url').default(''),
    location: text('location').default(''),
    category: text('category').default(''),
    isAvailable: boolean('is_available').default(true).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// ─────────────────────────────────────────────
// ORDERS
// ─────────────────────────────────────────────
export const orders = pgTable('orders', {
    id: uuid('id').primaryKey().defaultRandom(),
    buyerId: uuid('buyer_id').references(() => users.id, { onDelete: 'set null' }),
    productId: uuid('product_id').references(() => products.id, { onDelete: 'set null' }),
    quantity: integer('quantity').default(1).notNull(),
    totalPrice: integer('total_price').notNull(),
    status: text('status').default('placed').notNull(), // placed | confirmed | delivered | cancelled
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// ─────────────────────────────────────────────
// CONVERSATIONS (DM)
// ─────────────────────────────────────────────
export const conversations = pgTable('conversations', {
    id: uuid('id').primaryKey().defaultRandom(),
    participantIds: text('participant_ids').array().notNull(), // [userId1, userId2]
    lastMessageText: text('last_message_text').default(''),
    lastMessageSenderId: uuid('last_message_sender_id'),
    lastMessageAt: timestamp('last_message_at', { withTimezone: true }).defaultNow(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

// ─────────────────────────────────────────────
// MESSAGES
// ─────────────────────────────────────────────
export const messages = pgTable('messages', {
    id: uuid('id').primaryKey().defaultRandom(),
    conversationId: uuid('conversation_id').references(() => conversations.id, { onDelete: 'cascade' }).notNull(),
    senderId: uuid('sender_id').references(() => users.id, { onDelete: 'cascade' }).notNull(),
    text: text('text').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// ─────────────────────────────────────────────
// TypeScript Types
// ─────────────────────────────────────────────
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Post = typeof posts.$inferSelect;
export type NewPost = typeof posts.$inferInsert;
export type Comment = typeof comments.$inferSelect;
export type Community = typeof communities.$inferSelect;
export type Product = typeof products.$inferSelect;
export type MarketplacePost = typeof marketplacePosts.$inferSelect;
export type Order = typeof orders.$inferSelect;
export type Conversation = typeof conversations.$inferSelect;
export type Message = typeof messages.$inferSelect;
