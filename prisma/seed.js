const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function main() {
    // Create test user
    const hashedPassword = await bcrypt.hash('password123', 10);
    const user = await prisma.user.upsert({
        where: { email: 'test@example.com' },
        update: {},
        create: {
            email: 'test@example.com',
            name: 'Test User',
            password: hashedPassword,
            role: 'CONTRIBUTOR'
        }
    });

    // Create test category
    const category = await prisma.category.upsert({
        where: { slug: 'test-category' },
        update: {},
        create: {
            name: 'Test Category',
            slug: 'test-category',
            description: 'A test category for blog posts'
        }
    });

    // Create test posts
    const posts = [
        {
            title: 'First Test Post',
            slug: 'first-test-post',
            content: 'This is the content of our first test post. It contains some interesting information about testing and development.',
            published: true,
            authorId: user.id,
            categoryId: category.id
        },
        {
            title: 'Second Test Post',
            slug: 'second-test-post',
            content: 'Here is our second test post. It discusses various aspects of web development and best practices.',
            published: true,
            authorId: user.id,
            categoryId: category.id
        },
        {
            title: 'Third Test Post',
            slug: 'third-test-post',
            content: 'The third test post explores advanced topics in software engineering and system design.',
            published: true,
            authorId: user.id,
            categoryId: category.id
        }
    ];

    for (const post of posts) {
        await prisma.post.upsert({
            where: { slug: post.slug },
            update: {},
            create: post
        });
    }

    console.log('Database has been seeded with test data');
}

main()
    .catch((e) => {
        console.error(e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
