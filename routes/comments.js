const express = require('express');
const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const router = express.Router();
const prisma = new PrismaClient();

// Verify JWT middleware
const verifyToken = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'No token provided' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await prisma.user.findUnique({
            where: { id: decoded.userId },
            select: { id: true, name: true, email: true, role: true }
        });

        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid token' });
    }
};

// Get all comments for a post
router.get('/post/:postId', async (req, res) => {
    try {
        const comments = await prisma.comment.findMany({
            where: { postId: parseInt(req.params.postId) },
            include: {
                author: {
                    select: {
                        id: true,
                        name: true
                    }
                }
            },
            orderBy: {
                createdAt: 'desc'
            }
        });
        res.json(comments);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching comments' });
    }
});

// Get comment by ID
router.get('/:id', async (req, res) => {
    try {
        const comment = await prisma.comment.findUnique({
            where: { id: parseInt(req.params.id) },
            include: {
                author: {
                    select: {
                        id: true,
                        name: true
                    }
                },
                post: {
                    select: {
                        id: true,
                        title: true
                    }
                }
            }
        });
        if (!comment) {
            return res.status(404).json({ error: 'Comment not found' });
        }
        res.json(comment);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching comment' });
    }
});

// Create comment (requires authentication)
router.post('/', verifyToken, async (req, res) => {
    try {
        const { content, postId } = req.body;
        
        // Verify the post exists and is published
        const post = await prisma.post.findUnique({
            where: { id: parseInt(postId) }
        });

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        if (!post.published) {
            return res.status(400).json({ error: 'Cannot comment on unpublished posts' });
        }

        const comment = await prisma.comment.create({
            data: {
                content,
                author: { connect: { id: req.user.id } },
                post: { connect: { id: parseInt(postId) } }
            },
            include: {
                author: {
                    select: {
                        id: true,
                        name: true
                    }
                },
                post: {
                    select: {
                        id: true,
                        title: true
                    }
                }
            }
        });
        res.status(201).json(comment);
    } catch (error) {
        console.error('Error creating comment:', error);
        res.status(500).json({ error: 'Error creating comment' });
    }
});

// Update comment (only author can update)
router.put('/:id', verifyToken, async (req, res) => {
    try {
        const commentId = parseInt(req.params.id);
        
        // Check if comment exists and belongs to user
        const existingComment = await prisma.comment.findUnique({
            where: { id: commentId },
            include: { author: true }
        });

        if (!existingComment) {
            return res.status(404).json({ error: 'Comment not found' });
        }

        if (existingComment.author.id !== req.user.id) {
            return res.status(403).json({ error: 'Not authorized to update this comment' });
        }

        const { content } = req.body;
        const comment = await prisma.comment.update({
            where: { id: commentId },
            data: { content },
            include: {
                author: {
                    select: {
                        id: true,
                        name: true
                    }
                }
            }
        });
        res.json(comment);
    } catch (error) {
        res.status(500).json({ error: 'Error updating comment' });
    }
});

// Delete comment (only author or admin can delete)
router.delete('/:id', verifyToken, async (req, res) => {
    try {
        const commentId = parseInt(req.params.id);
        
        // Check if comment exists
        const existingComment = await prisma.comment.findUnique({
            where: { id: commentId },
            include: { author: true }
        });

        if (!existingComment) {
            return res.status(404).json({ error: 'Comment not found' });
        }

        // Check if user is author or admin
        if (existingComment.author.id !== req.user.id && req.user.role !== 'ADMIN') {
            return res.status(403).json({ error: 'Not authorized to delete this comment' });
        }

        await prisma.comment.delete({
            where: { id: commentId }
        });
        res.json({ message: 'Comment deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Error deleting comment' });
    }
});

module.exports = router;
