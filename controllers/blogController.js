const mongoose = require('mongoose');
const BlogPost = require('../models/BlogPost');
const { v2: cloudinary } = require('cloudinary');

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// @desc    Create a new blog post
// @route   POST /api/blog/posts
// @access  Private/Admin
exports.createBlogPost = async (req, res) => {
  console.log('Creating blog post with data:', req.body);
  console.log('Uploaded files:', req.files);
  
  try {
    const {
      title,
      content,
      category,
      subcategory,
      authorName = 'Admin',
      status = 'draft',
      tags = '[]',
      keywords = '[]'
    } = req.body;

    // Handle file uploads if any
    let featuredImage = null;
    let bannerImage = null;

    // For local file storage
    if (req.files?.featuredImage) {
      const file = req.files.featuredImage[0];
      featuredImage = {
        url: `/uploads/${file.filename}`,
        publicId: file.filename
      };
    }

    if (req.files?.bannerImage) {
      const file = req.files.bannerImage[0];
      bannerImage = {
        url: `/uploads/${file.filename}`,
        publicId: file.filename
      };
    }

    // Parse tags and keywords if they're strings
    const parsedTags = typeof tags === 'string' ? JSON.parse(tags) : (Array.isArray(tags) ? tags : []);
    const parsedKeywords = typeof keywords === 'string' ? JSON.parse(keywords) : (Array.isArray(keywords) ? keywords : []);

    // Create new blog post
    const blogPostData = {
      title,
      slug: title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, ''),
      content,
      category,
      subcategory: subcategory || 'Article',
      authorName,
      status,
      tags: parsedTags,
      keywords: parsedKeywords,
      featuredImage,
      bannerImage,
      author: req.user?.id || null
    };
    
    console.log('Creating blog post with data:', blogPostData);
    const blogPost = await BlogPost.create(blogPostData);
    console.log('Blog post created successfully:', blogPost);

    res.status(201).json({
      success: true,
      data: blogPost
    });
  } catch (error) {
    console.error('Error creating blog post:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating blog post',
      error: error.message
    });
  }
};

// @desc    Get all blog posts
// @route   GET /api/blog/posts
// @access  Public
exports.getBlogPosts = async (req, res) => {
  console.log('Fetching blog posts with query:', req.query);
  try {
    const { page = 1, limit = 10, status, category, search } = req.query;
    const query = {};

    if (status) query.status = status;
    if (category) query.category = category;
    
    if (search) {
      query.$text = { $search: search };
    }

    console.log('MongoDB query:', query);
    const posts = await BlogPost.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .lean()
      .exec();

    console.log('Found posts:', posts);
    const count = await BlogPost.countDocuments(query);
    console.log('Total posts count:', count);

    res.status(200).json({
      success: true,
      data: posts,
      totalPages: Math.ceil(count / limit),
      currentPage: page
    });
  } catch (error) {
    console.error('Error fetching blog posts:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching blog posts',
      error: error.message
    });
  }
};

// @desc    Get single blog post by slug or ID
// @route   GET /api/blog/posts/:slug
// @access  Public
exports.getBlogPostBySlug = async (req, res) => {
  try {
    const identifier = req.params.slug;
    
    // Try to find by slug first
    let post = await BlogPost.findOneAndUpdate(
      { slug: identifier },
      { $inc: { views: 1 } },
      { new: true }
    );

    // If not found by slug, try to find by _id (MongoDB ObjectId)
    if (!post) {
      // Check if identifier is a valid MongoDB ObjectId
      const mongoose = require('mongoose');
      if (mongoose.Types.ObjectId.isValid(identifier)) {
        post = await BlogPost.findOneAndUpdate(
          { _id: identifier },
          { $inc: { views: 1 } },
          { new: true }
        );
      }
    }

    // If still not found, try case-insensitive slug search
    if (!post) {
      post = await BlogPost.findOneAndUpdate(
        { slug: { $regex: new RegExp(`^${identifier}$`, 'i') } },
        { $inc: { views: 1 } },
        { new: true }
      );
    }

    if (!post) {
      return res.status(404).json({
        success: false,
        message: 'Blog post not found'
      });
    }

    res.status(200).json({
      success: true,
      data: post
    });
  } catch (error) {
    console.error('Error fetching blog post:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching blog post',
      error: error.message
    });
  }
};

// @desc    Update a blog post
// @route   PUT /api/blog/posts/:id
// @access  Private/Admin
exports.updateBlogPost = async (req, res) => {
  try {
    const updates = { ...req.body };
    
    // Handle file uploads if any
    if (req.files?.featuredImage) {
      const result = await cloudinary.uploader.upload(req.files.featuredImage[0].path, {
        folder: 'blog/featured'
      });
      updates.featuredImage = {
        url: result.secure_url,
        publicId: result.public_id
      };
    }

    if (req.files?.bannerImage) {
      const result = await cloudinary.uploader.upload(req.files.bannerImage[0].path, {
        folder: 'blog/banner'
      });
      updates.bannerImage = {
        url: result.secure_url,
        publicId: result.public_id
      };
    }

    // Convert tags and keywords to arrays if they're strings
    if (updates.tags && typeof updates.tags === 'string') {
      updates.tags = JSON.parse(updates.tags);
    }
    
    if (updates.keywords && typeof updates.keywords === 'string') {
      updates.keywords = JSON.parse(updates.keywords);
    }

    const { id } = req.params;
    let post = null;

    if (mongoose.Types.ObjectId.isValid(id)) {
      post = await BlogPost.findByIdAndUpdate(
        id,
        { $set: updates },
        { new: true, runValidators: true }
      );
    }

    if (!post) {
      post = await BlogPost.findOneAndUpdate(
        { slug: id },
        { $set: updates },
        { new: true, runValidators: true }
      );
    }

    if (!post) {
      return res.status(404).json({
        success: false,
        message: 'Blog post not found'
      });
    }

    res.status(200).json({
      success: true,
      data: post
    });
  } catch (error) {
    console.error('Error updating blog post:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating blog post',
      error: error.message
    });
  }
};

// @desc    Delete a blog post
// @route   DELETE /api/blog/posts/:id
// @access  Private/Admin
exports.deleteBlogPost = async (req, res) => {
  try {
    const post = await BlogPost.findById(req.params.id);

    if (!post) {
      return res.status(404).json({
        success: false,
        message: 'Blog post not found'
      });
    }

    // Delete images from Cloudinary if they exist
    if (post.featuredImage?.publicId) {
      await cloudinary.uploader.destroy(post.featuredImage.publicId);
    }
    
    if (post.bannerImage?.publicId) {
      await cloudinary.uploader.destroy(post.bannerImage.publicId);
    }

    // Use deleteOne() instead of remove() which is deprecated
    await BlogPost.deleteOne({ _id: post._id });

    res.status(200).json({
      success: true,
      message: 'Blog post deleted successfully',
      data: { id: post._id }
    });
  } catch (error) {
    console.error('Error deleting blog post:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting blog post',
      error: error.message
    });
  }
};
