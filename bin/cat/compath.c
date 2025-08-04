#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int	 trie(int, int, char **);

struct node {
	struct node	**children;
	size_t		 csiz;
	size_t		 clen;
	char		*component;
	int		 weight;
};

static struct node *
insert(struct node *n, char *component, int *alloced)
{
	struct node	*new;
	void		*t;
	char		*dup;
	size_t		 newsiz;
	size_t		 i;

	*alloced = 0;
	for (i = 0; i < n->clen; ++i) {
		if (!strcmp(n->children[i]->component, component))
			return (n->children[i]);
	}

	if (n->csiz == 0 || n->clen == n->csiz) {
		if (n->csiz >= SIZE_MAX / 2) {
			errno = EOVERFLOW;
			return (NULL);
		}
		newsiz = n->csiz * 2;
		if (newsiz == 0)
			newsiz = 8;

		t = reallocarray(n->children, newsiz, sizeof(*n));
		if (t == NULL)
			return (NULL);

		n->children = t;
		n->csiz = newsiz;
	}

	if ((new = calloc(1, sizeof(*new))) == NULL)
		return (NULL);

	if ((dup = strdup(component)) == NULL) {
		free(new);
		return (NULL);
	}

	new->component = dup;
	n->children[n->clen++] = new;
	*alloced = 1;

	return (new);
}

static void
recfree(struct node *n)
{
	size_t		 i;

	for (i = 0; i < n->clen; ++i)
		recfree(n->children[i]);
	free(n->children);
	free(n->component);
	free(n);
}

static int
insertpath(struct node *root, char *path)
{
	struct node	*stack[256];
	size_t		 i, s = 0;
	struct node	*n = root;
	char		*comp;
	int		 weight, new;

	if (!strcmp(path, "/")) {
		n = root;
		goto done;
	}

	stack[s++] = root;
	while ((comp = strsep(&path, "/")) != NULL) {
		if (*comp == '\0')
			continue;

		if ((n = insert(n, comp, &new)) == NULL)
			return (-1);

		/*
		 * found a more generic one, no need to insert this
		 * the rest of this path.
		 */
		if (!new && n->clen == 0)
			return (0);

		if (s == 256) {
			errno = ENAMETOOLONG;
			return (-1);
		}
		stack[s++] = n;
	}

 done:
	/*
	 * remove all the descendant (if any) since we're more generic
	 * than them.  be careful to adjust the weights though.
	 */
	weight = 0;
	for (i = 0; i < n->clen; ++i) {
		weight += n->children[i]->weight;
		recfree(n->children[i]);
	}
	free(n->children);
	n->children = NULL;
	n->clen = n->csiz = 0;

	for (i = 0; i < s; ++i)
		stack[i]->weight += 1 - weight;

	return (0);
}

/* based on canonpath from kern_pledge.c */
static int
canonpath(const char *cwd, const char *input, char *buf, size_t bufsize)
{
	const char *p;
	char *q, path[PATH_MAX];
	int r;

	if (*input != '/') {
		r = snprintf(path, sizeof(path), "%s/%s", cwd, input);
		if (r < 0 || (size_t)r >= sizeof(path)) {
			errno = ENAMETOOLONG;
			return -1;
		}
		input = path;
	}

	p = input;
	q = buf;
	while (*p && (q - buf < bufsize)) {
		if (p[0] == '/' && (p[1] == '/' || p[1] == '\0')) {
			p += 1;

		} else if (p[0] == '/' && p[1] == '.' &&
		    (p[2] == '/' || p[2] == '\0')) {
			p += 2;

		} else if (p[0] == '/' && p[1] == '.' && p[2] == '.' &&
		    (p[3] == '/' || p[3] == '\0')) {
			p += 3;
			if (q != buf)	/* "/../" at start of buf */
				while (*--q != '/')
					continue;

		} else {
			*q++ = *p++;
		}
	}
	if ((*p == '\0') && (q - buf < bufsize)) {
		*q = 0;
		return 0;
	} else {
		errno = ENAMETOOLONG;
		return -1;
	}
}

static void
dump_rec(struct node *n, int depth)
{
	const char	*name;
	int		 i;
	int		 d = depth;

	for (i = 0; i < d; ++i)
		fputc(' ', stderr);

	name = n->component;
	if (name == NULL)
		name = "/";

	fprintf(stderr, "%s", name);

	for (i = depth + strlen(name); i < 30; ++i)
		fputc(' ', stderr);
	fprintf(stderr, " %d\n", n->weight);

	for (i = 0; i < n->clen; ++i)
		dump_rec(n->children[i], depth + 4);
}

static void
recut(struct node *q, char path[PATH_MAX], int prefix, int target, int level)
{
	const char	*name;
	int		 stop;
	size_t		 i;

	name = q->component;
	if (name == NULL)
		name = "";

	/* cannot happen by construction */
	if (prefix + 1 + strlen(name) >= PATH_MAX)
		abort();

	if (prefix == 0 || path[prefix-1] != '/')
		path[prefix++] = '/';

	memcpy(path + prefix, name, strlen(name) + 1);
	prefix += strlen(name);

	stop = level >= target && q->weight > 1 && q->clen > 1;

	if (stop || q->clen == 0) {
		if (unveil(path, "r") == -1)
			err(1, "unveil %s", path);
		fprintf(stderr, "%d %d %zu unveil(%s)\n", level, target, q->clen, path);
	}

	if (stop)
		return;

	for (i = 0; i < q->clen; ++i)
		recut(q->children[i], path, prefix, target, level+1);
}

static void
cut(struct node *root, int target)
{
	char		 path[PATH_MAX];

	recut(root, path, 0, target, 0);
}

static void
traverse(struct node *root, int limit)
{
	struct node	*n;
	struct node	*q[256];
	struct node	*qt[256];
	size_t		 nq = 0, nqt = 0;
	size_t		 i, j, level;
	int		 target = -1;

	q[nq++] = root;
	for (level = 0; ; ++level) {
		if (nq > limit)
			break;
		target = level;

		nqt = 0;
		for (i = 0; i < nq; ++i) {
			n = q[i];
			for (j = 0; j < n->clen; ++j) {
				if (nqt == 256)
					abort();
				qt[nqt++] = n->children[j];
			}
		}
		if (nqt == 0)
			break;

		memcpy(q, qt, nqt * sizeof(*qt));
		nq = nqt;
	}

	fprintf(stderr, "target is level %d\n", target);
	fprintf(stderr, "items cut down to:\n");

	cut(root, target);
}

/* don't mind the leaks :p */
int
compath(int limit, int argc, char **argv)
{
	char		 cwd[PATH_MAX], path[PATH_MAX];
	int		 i;
	struct node	*root;

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		return (-1);

	if ((root = calloc(1, sizeof(*root))) == NULL)
		return (-1);


	for (i = 0; i < argc; ++i) {
		if (canonpath(cwd, argv[i], path, sizeof(path)) == -1)
			return (-1);

		if (insertpath(root, path) == -1)
			return (-1);
	}

	fputs("===============================\n", stderr);
	dump_rec(root, 0);
	fputs("===============================\n", stderr);

	traverse(root, limit);

	recfree(root);

	return (0);
}
