#include <stdio.h>
#include "slab.h"
static hurd_slab_space_t slab;

struct foo {
    int val;
    struct foo *next;
};
struct foo *foo;

struct foo **find(int v)
{
    struct foo **f;
    for(f = &foo; *f != NULL; f = &(*f)->next) {
        if(v == (*f)->val) {
            return f;
        }
    }
    return NULL;
}

struct foo *new_foo()
{
    void *p = NULL;
    hurd_slab_alloc(slab, &p);
    return p;
}

void del_foo(struct foo *f)
{
    hurd_slab_dealloc(slab, f);

}

void show()
{
   struct foo *p = foo;
    while(p) {
        printf("%d\n", p->val);
        p = p->next;
    }

}

int main()
{
    int i;
    struct foo *h, *p, *q, *t;
    struct foo **pp;

    hurd_slab_create(sizeof(struct foo), 0, NULL, NULL, NULL, NULL, NULL, &slab);


    p = new_foo();
    p->val = 0;
    foo = p;
    h = p;
    for(i = 0; i < 10; i++) {
        q = new_foo();
        q->val = i+1;
        q->next = NULL;
        p->next = q;
        p = q;
    }
    p = h;
    while(p) {
        printf("%d\n", p->val);
        p = p->next;
    }

    if(pp = find(4)) {
        p = *pp;
        *pp = (*pp)->next;
        del_foo(p); 
        del_foo(p);
   }
    if(pp = find(5)) {
        p = *pp;
        *pp = (*pp)->next;
        del_foo(p);
    }
    show();
    p = new_foo();
    p->val = 100;
    p->next = foo;
    show();
    pp = find(10);
    p = *pp;
    *pp = (*pp)->next;
    del_foo(p);
    show();

}
