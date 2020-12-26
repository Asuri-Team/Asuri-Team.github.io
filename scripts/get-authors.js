'use strict';

let authors = [];

hexo.extend.filter.register('before_generate', function () {
    const Author = this.model('Author');
    const Post = this.model('Post');

    const _authors = Author.find({});

    authors = _authors.data.map(author => {
        author = { ...author };

        const post = Post
            .find({ authorId: author.name })
            .sort({ updated: 'desc' })
            .limit(1);

        if (post.data && post.data.length) {
            const updated = +post.data[0].updated;
            if (!author.lastUpdate || updated > author.lastUpdate) {
                author.lastUpdate = updated;
            }
        }

        return author;
    });
});

hexo.extend.filter.register('template_locals', function (locals) {
    locals.authors = {
        active: authors.filter(t => t.active),
        inactive: authors.filter(t => !t.active),
    };
    return locals;
});
