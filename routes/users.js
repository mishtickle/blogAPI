const express = require('express');
const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const router = express.Router();
const prisma = new PrismaClient();

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';

// Admin authorization middleware
const isAdmin = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'No token provided' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await prisma.user.findUnique({
            where: { id: decoded.userId },
            select: { id: true, role: true }
        });

        if (!user || user.role !== 'ADMIN') {
            return res.status(403).json({ message: 'Not authorized' });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('Admin authorization error:', error);
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Get all users (Admin only)
router.get('/', isAdmin, async (req, res) => {
    try {
        const users = await prisma.user.findMany({
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                createdAt: true,
                _count: {
                    select: {
                        posts: true,
                        comments: true
                    }
                }
            }
        });
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ message: 'Error fetching users', error: error.message });
    }
});

// Get user by ID (Admin only)
router.get('/:id', isAdmin, async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: { id: parseInt(req.params.id) },
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                createdAt: true,
                posts: {
                    select: {
                        id: true,
                        title: true,
                        published: true,
                        createdAt: true
                    }
                },
                comments: {
                    select: {
                        id: true,
                        content: true,
                        createdAt: true,
                        post: {
                            select: {
                                id: true,
                                title: true
                            }
                        }
                    }
                }
            }
        });
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        res.json(user);
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ message: 'Error fetching user', error: error.message });
    }
});

// Update user role (Admin only)
router.patch('/:id/role', isAdmin, async (req, res) => {
    try {
        const { role } = req.body;
        const userId = parseInt(req.params.id);

        // Validate role
        if (!['USER', 'CONTRIBUTOR', 'ADMIN'].includes(role)) {
            return res.status(400).json({ message: 'Invalid role' });
        }

        // Prevent admin from changing their own role
        if (userId === req.user.id) {
            return res.status(403).json({ message: 'Cannot change your own role' });
        }

        const updatedUser = await prisma.user.update({
            where: { id: userId },
            data: { role },
            select: {
                id: true,
                email: true,
                name: true,
                role: true
            }
        });

        res.json(updatedUser);
    } catch (error) {
        console.error('Error updating user role:', error);
        res.status(500).json({ message: 'Error updating user role', error: error.message });
    }
});

// Delete user (Admin only)
router.delete('/:id', isAdmin, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);

        // Prevent admin from deleting themselves
        if (userId === req.user.id) {
            return res.status(403).json({ message: 'Cannot delete your own account' });
        }

        await prisma.user.delete({
            where: { id: userId }
        });

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ message: 'Error deleting user', error: error.message });
    }
});

module.exports = router;
