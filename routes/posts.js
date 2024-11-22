const express = require('express');
const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const router = express.Router();
const prisma = new PrismaClient();

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';

// Middleware to verify JWT token
const verifyToken = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'No token provided' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        if (!decoded.userId) {
            return res.status(401).json({ message: 'Invalid token format' });
        }

        const user = await prisma.user.findUnique({
            where: { id: decoded.userId },
            select: { id: true, name: true, role: true }
        });

        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        return res.status(401).json({ message: 'Invalid token' });
    }
};

// Admin authorization middleware
const isAdmin = async (req, res, next) => {
    if (req.user.role !== 'ADMIN') {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

// Helper function to generate slug
function generateSlug(title) {
    return title
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/(^-|-$)/g, '');
}

// Helper function to ensure unique slug
async function ensureUniqueSlug(baseSlug) {
    let slug = baseSlug;
    let counter = 1;
    
    while (true) {
        // Check if slug exists
        const existingPost = await prisma.post.findUnique({
            where: { slug }
        });
        
        if (!existingPost) {
            return slug;
        }
        
        // If slug exists, append counter and try again
        slug = `${baseSlug}-${counter}`;
        counter++;
    }
}

// Get all posts (Admin only)
router.get('/', verifyToken, isAdmin, async (req, res) => {
    try {
        const posts = await prisma.post.findMany({
            include: {
                author: {
                    select: {
                        id: true,
                        name: true,
                        email: true
                    }
                },
                category: true,
                _count: {
                    select: {
                        comments: true
                    }
                }
            },
            orderBy: {
                createdAt: 'desc'
            }
        });

        res.json(posts);
    } catch (error) {
        console.error('Error fetching posts:', error);
        res.status(500).json({ message: 'Error fetching posts', error: error.message });
    }
});

// Get posts for current user (Contributor)
router.get('/my-posts', verifyToken, async (req, res) => {
    try {
        // Check if user is a contributor or admin
        if (req.user.role !== 'CONTRIBUTOR' && req.user.role !== 'ADMIN') {
            return res.status(403).json({ message: 'Contributor access required' });
        }

        console.log('Fetching posts for user:', req.user.id, 'with role:', req.user.role);

        const posts = await prisma.post.findMany({
            where: {
                authorId: req.user.id
            },
            include: {
                author: {
                    select: {
                        id: true,
                        name: true
                    }
                },
                category: true
            },
            orderBy: {
                createdAt: 'desc'
            }
        });

        console.log('Found posts:', posts.length);

        res.json({ posts });
    } catch (error) {
        console.error('Error fetching user posts:', error);
        res.status(500).json({ 
            message: 'Error fetching posts', 
            error: error.message,
            userId: req.user?.id,
            userRole: req.user?.role 
        });
    }
});

// Get public posts with optional filters
router.get('/public', async (req, res) => {
    try {
        const { category, year, month, limit = 10, page = 1 } = req.query;
        const skip = (page - 1) * parseInt(limit);

        // Build where clause based on filters
        const where = {
            published: true
        };

        if (category) {
            where.categoryId = parseInt(category);
        }

        if (year && month) {
            const startDate = new Date(parseInt(year), parseInt(month) - 1, 1);
            const endDate = new Date(parseInt(year), parseInt(month), 0);
            where.createdAt = {
                gte: startDate,
                lte: endDate
            };
        }

        // Get posts and total count in a transaction
        const [posts, total] = await prisma.$transaction([
            prisma.post.findMany({
                where,
                include: {
                    author: {
                        select: {
                            id: true,
                            name: true
                        }
                    },
                    category: true,
                    comments: {
                        select: {
                            id: true,
                            content: true,
                            createdAt: true,
                            author: {
                                select: {
                                    name: true
                                }
                            }
                        },
                        take: 2,
                        orderBy: {
                            createdAt: 'desc'
                        }
                    }
                },
                orderBy: {
                    createdAt: 'desc'
                },
                skip,
                take: parseInt(limit)
            }),
            prisma.post.count({ where })
        ]);

        // Transform the response to include only necessary data
        const transformedPosts = posts.map(post => ({
            id: post.id,
            title: post.title,
            slug: post.slug || post.id.toString(),
            content: post.content,
            published: post.published,
            createdAt: post.createdAt,
            author: post.author ? {
                id: post.author.id,
                name: post.author.name
            } : null,
            category: post.category ? {
                id: post.category.id,
                name: post.category.name
            } : null,
            comments: post.comments.map(comment => ({
                id: comment.id,
                content: comment.content,
                createdAt: comment.createdAt,
                author: comment.author ? {
                    name: comment.author.name
                } : null
            }))
        }));

        // Log the response for debugging
        console.log('Posts response:', {
            posts: transformedPosts,
            pagination: {
                total,
                pages: Math.ceil(total / parseInt(limit)),
                currentPage: parseInt(page),
                limit: parseInt(limit)
            }
        });

        res.json({
            posts: transformedPosts,
            pagination: {
                total,
                pages: Math.ceil(total / parseInt(limit)),
                currentPage: parseInt(page),
                limit: parseInt(limit)
            }
        });
    } catch (error) {
        console.error('Error fetching public posts:', error);
        res.status(500).json({ 
            message: 'Error fetching posts', 
            error: error.message 
        });
    }
});

// Search posts
router.get('/search', async (req, res) => {
    try {
        const { q } = req.query;
        if (!q) {
            return res.status(400).json({ error: 'Search query is required' });
        }

        const posts = await prisma.post.findMany({
            where: {
                published: true,
                OR: [
                    { title: { contains: q, mode: 'insensitive' } },
                    { content: { contains: q, mode: 'insensitive' } }
                ]
            },
            orderBy: {
                createdAt: 'desc'
            },
            include: {
                author: {
                    select: {
                        id: true,
                        name: true
                    }
                },
                category: {
                    select: {
                        name: true,
                        slug: true
                    }
                }
            }
        });

        res.json(posts);
    } catch (error) {
        console.error('Error searching posts:', error);
        res.status(500).json({ error: 'Error searching posts' });
    }
});

// Get post archives
router.get('/archives', async (req, res) => {
    try {
        const posts = await prisma.post.findMany({
            where: {
                published: true
            },
            select: {
                createdAt: true
            },
            orderBy: {
                createdAt: 'desc'
            }
        });

        const archives = {};
        posts.forEach(post => {
            const date = new Date(post.createdAt);
            const year = date.getFullYear();
            const month = date.toLocaleString('default', { month: 'long' });

            if (!archives[year]) {
                archives[year] = {};
            }
            if (!archives[year][month]) {
                archives[year][month] = 0;
            }
            archives[year][month]++;
        });

        res.json(archives);
    } catch (error) {
        console.error('Error fetching archives:', error);
        res.status(500).json({ error: 'Error fetching archives' });
    }
});

// Get single post by slug
router.get('/by-slug/:slug', async (req, res) => {
    try {
        const { slug } = req.params;
        
        const post = await prisma.post.findUnique({
            where: { slug },
            include: {
                author: {
                    select: {
                        id: true,
                        name: true
                    }
                },
                category: true,
                comments: {
                    include: {
                        author: {
                            select: {
                                name: true
                            }
                        }
                    },
                    orderBy: {
                        createdAt: 'desc'
                    }
                }
            }
        });

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        // If post is not published, only return it to the author or admin
        if (!post.published) {
            const token = req.headers.authorization?.split(' ')[1];
            if (!token) {
                return res.status(404).json({ error: 'Post not found' });
            }

            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                const user = await prisma.user.findUnique({
                    where: { id: decoded.userId },
                    select: { id: true, role: true }
                });

                if (!user || (user.id !== post.authorId && user.role !== 'ADMIN')) {
                    return res.status(404).json({ error: 'Post not found' });
                }
            } catch (error) {
                return res.status(404).json({ error: 'Post not found' });
            }
        }

        res.json(post);
    } catch (error) {
        console.error('Error fetching post:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get post by ID
router.get('/:id', async (req, res) => {
  try {
    const post = await prisma.post.findUnique({
      where: { id: parseInt(req.params.id) },
      include: {
        author: {
          select: {
            id: true,
            name: true,
            email: true
          }
        },
        comments: {
          include: {
            author: {
              select: {
                id: true,
                name: true
              }
            }
          }
        }
      }
    });
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }
    res.json(post);
  } catch (error) {
    res.status(500).json({ error: 'Error fetching post' });
  }
});

// Create new post
router.post('/', verifyToken, async (req, res) => {
    try {
        const { title, content, categoryId, published = false } = req.body;
        const userId = req.user.id;

        // Validate required fields
        if (!title || !content) {
            return res.status(400).json({ message: 'Title and content are required' });
        }

        // Check if category exists
        const category = await prisma.category.findUnique({
            where: { id: parseInt(categoryId) }
        });

        if (!category) {
            return res.status(400).json({ message: 'Invalid category' });
        }

        // Generate and ensure unique slug
        const baseSlug = generateSlug(title);
        const uniqueSlug = await ensureUniqueSlug(baseSlug);

        const post = await prisma.post.create({
            data: {
                title,
                content,
                published,
                slug: uniqueSlug,
                authorId: userId,
                categoryId,
            },
            include: {
                author: {
                    select: {
                        id: true,
                        name: true
                    }
                },
                category: {
                    select: {
                        id: true,
                        name: true,
                        slug: true
                    }
                }
            }
        });

        res.status(201).json(post);
    } catch (error) {
        console.error('Error creating post:', error);
        res.status(500).json({ message: 'Error creating post' });
    }
});

// Update post
router.put('/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, content, published } = req.body;

        // Check if post exists and belongs to user
        const existingPost = await prisma.post.findUnique({
            where: { id: parseInt(id) }
        });

        if (!existingPost) {
            return res.status(404).json({ message: 'Post not found' });
        }

        if (existingPost.authorId !== req.user.id) {
            return res.status(403).json({ message: 'Not authorized to update this post' });
        }

        const post = await prisma.post.update({
            where: { id: parseInt(id) },
            data: {
                title,
                content,
                published,
                slug: title.toLowerCase().replace(/[^\w\s-]/g, '').replace(/\s+/g, '-')
            }
        });

        res.json(post);
    } catch (error) {
        console.error('Error updating post:', error);
        res.status(500).json({ message: 'Error updating post' });
    }
});

// Publish post (Admin only)
router.put('/:id/publish', verifyToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        const post = await prisma.post.update({
            where: { id: parseInt(id) },
            data: { published: true },
            include: {
                author: {
                    select: {
                        id: true,
                        name: true,
                        email: true
                    }
                },
                category: true
            }
        });

        res.json(post);
    } catch (error) {
        console.error('Error publishing post:', error);
        res.status(500).json({ message: 'Failed to publish post' });
    }
});

// Approve post (Admin only)
router.patch('/:id/approve', verifyToken, isAdmin, async (req, res) => {
    try {
        const postId = parseInt(req.params.id);
        const post = await prisma.post.update({
            where: { id: postId },
            data: { published: true },
            include: {
                author: {
                    select: {
                        id: true,
                        name: true,
                        email: true
                    }
                },
                category: true
            }
        });

        res.json(post);
    } catch (error) {
        console.error('Error approving post:', error);
        res.status(500).json({ message: 'Error approving post', error: error.message });
    }
});

// Delete post (Admin or author only)
router.delete('/:id', verifyToken, async (req, res) => {
    try {
        const postId = parseInt(req.params.id);
        
        // Check if user is admin or post author
        const post = await prisma.post.findUnique({
            where: { id: postId },
            select: { authorId: true }
        });

        if (!post) {
            return res.status(404).json({ message: 'Post not found' });
        }

        if (req.user.role !== 'ADMIN' && post.authorId !== req.user.id) {
            return res.status(403).json({ message: 'Not authorized to delete this post' });
        }

        // Use a transaction to ensure atomic operations
        await prisma.$transaction(async (tx) => {
            // First delete all comments
            await tx.comment.deleteMany({
                where: { postId: postId }
            });

            // Then delete the post
            await tx.post.delete({
                where: { id: postId }
            });
        });

        res.json({ message: 'Post deleted successfully' });
    } catch (error) {
        console.error('Error deleting post:', error);
        res.status(500).json({ message: 'Error deleting post', error: error.message });
    }
});

// Add comment to a post
router.post('/:slug/comments', verifyToken, async (req, res) => {
    try {
        const { slug } = req.params;
        const { content } = req.body;
        const userId = req.user.id;

        if (!content || typeof content !== 'string' || content.trim().length === 0) {
            return res.status(400).json({ error: 'Comment content is required' });
        }

        const post = await prisma.post.findUnique({
            where: { slug }
        });

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        const comment = await prisma.comment.create({
            data: {
                content,
                authorId: userId,
                postId: post.id
            },
            include: {
                author: {
                    select: {
                        name: true
                    }
                }
            }
        });

        res.json(comment);
    } catch (error) {
        console.error('Error creating comment:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
