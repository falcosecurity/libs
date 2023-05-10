How to contribute
===

# Coding style 💻

## Introduction

This document introduces the coding style that will be applied in this repository.
This coding style involves all the following files: `.c`, `.h`, `.cpp`, `.cmake`, `CMakeLists.txt`. To enforce it we rely on two main tools:

1. `clang-format` version `14.0.0`.
2. `cmake-format` version `0.6.13`.

> __Please note__: tools versions are important! Different versions will enforce slightly different changes on the code. For example `clang-format-14` will produce a slightly different output respect to `clang-format-13` always respecting the imposed style.

The coding style is expressed through the 2 configuration file that you find in this repo: `.clang-format`, `.cmake-format.json`.  

## Enforce the style locally

There are many ways to enforce the style locally, here we will describe two of them:

1. Use the repo `Makefile`.
2. Use `pre-commit` framework.

### 1.Makefile

#### Step 1

In order to use the repo `Makefile`, you need to install on your local machine the two aforementioned tools:

__clang-format v14.0.0__

One of the easiest ways to install `clang-format` could be directly downloading its static binary from [here](https://github.com/muttleyxd/clang-tools-static-binaries).
There are other ways for example you can download the package for your distro or you can also build it from sources.

__cmake-format v0.6.13__

To install `cmake-format` you can follow the official documentation [here](https://cmake-format.readthedocs.io/en/latest/installation.html).

> __NOTE__: Please check the versions of the two tool with `clang-format --version` and `cmake-format --version`.

#### Step 2

Once you have installed the __right__ versions of the 2 tools, you can simply type `make format-all` from the root directory of the project (`/libs`) to format all your code according to the coding style.

Remember to do that before submitting a new patch upstream! 😁

### 2.Pre-commit framework (suggested if you don't have the 2 tools already installed on your machine)

The `pre-commit` framework allows you to automatically install different `git-hooks` that will run at every new commit. More precisely, if you use the `.pre-commit-config.yaml` in this repo you will install 3 different hooks:

1. The `clang-format` hook: this is a `pre-commit` git hook that runs `clang-format` on your staged changes.
2. The `cmake-format` hook: this is a `pre-commit` git hook that runs `cmake-format` on your staged changes.
3. The `DCO signed-off` hook: this is a `pre-commit-msg` git hook that adds the `DCO` on your commit if not present. This hook is not strictly related to the coding style so we will talk about it in a separate section: [Add DCO signed-off to your commits](#add-dco-signed-off-to-your-commits).

Now let's see what we need to use `pre-commit` framework.

#### Step 1

Install `pre-commit` framework following the [official documentation](https://pre-commit.com/#installation).

> __Please note__: you have to follow only the "Installation" section.

#### Step 2

Once you have installed `pre-commit`, you don't need to install anything else! This is the good point of using a framework like `pre-commit`, all the tools necessary to format your code will be directly managed by the framework. But in order to be ready, you need to install the git hooks in your local repo.

This simple command allows you to install the two `pre-commit` git hooks, `clang-format` and `cmake-format`.

```bash
pre-commit install --install-hooks --hook-type pre-commit --overwrite  
```

If you want to install also the `pre-commit-msg` git hook for the DCO you have to type the following command, but be sure to have configured all you need as said in the [dedicated section]((#add-dco-signed-off-to-your-commits))

```bash
pre-commit install --install-hooks --hook-type prepare-commit-msg --overwrite 
```

You have done, at every new commit, this hook will check that your patch respects the coding style of this repo!

If you want to detach the git hooks, you can simply type:

```bash
pre-commit uninstall --hook-type prepare-commit-msg
pre-commit uninstall --hook-type pre-commit 
```

### Other solutions

Obviously, you can also install the 2 tools locally and enable some extension of your favorite IDE (like `VScode`) to format your code every time you save your files!

## Enforce the style remotely (CI/CD)

To enforce the code style we use a *Github action Workflow* called `Linting code`.
In this workflow we have 2 main jobs:

1. `clang-format`: checks if all the codebase is compliant with the code style. If not, it posts a comment in the pull request with the link to the diff (`clang_format_diff.patch`).
2. `cmake-format`: checks if all the codebase is compliant with the code style. If not, it posts a comment in the pull request with the link to the diff (`cmake_format_diff.patch`).

# Add DCO signed-off to your commits 🔏

## Introduction

Another requirement for contributing to the `libs` repository, is applying the [DCO](https://cert-manager.io/docs/contributing/sign-off/) to every commit you want to push upstream.
Before doing this you have to configure your git user `name` and `email` if you haven't already done it. To check your actual `name` and `email` type:

```bash
git config --get user.name
git config --get user.email
```

If they are correct you have done, otherwise, you have to set them:

```bash
git config user.name <full-name>
git config user.email <mail-used_with-GitHub-profile>
```

>__Please note__: If you have problems in doing this you can read the full documentation [here](https://docs.github.com/en/get-started/getting-started-with-git/setting-your-username-in-git).

## Enforce the DCO locally

Now you are ready to sign your commits! You have two main ways to do this:

1. Manually with `git` tool.
2. Use the `pre-commit-msg` hook quoted before.

### Manually

To do this you just need to remember the `-s` while performing your commits:

```bash
git commit -s
```

or with the inline message:

```bash
git commit -s -m "my first commit"
```

### Use `pre-commit` hook

Here if you have already added the hook in the [previous section](#step-2), you have to do nothing otherwise you have to simply install the DCO hook with:

```bash
pre-commit install --install-hooks --hook-type prepare-commit-msg --overwrite 
```

And you have done! Now you don't have to remember the `-s` option every time you commit something, the DCO hook will automatically add the DCO if you forget it! 😄

## Enforce the DCO remotely (CI/CD)

The `dco` job: will check the DCO presence on __all__ your commits.

# Some best practices 📏

## Class variables

To know whether a variable belongs to a `class` or a `function`, we start member variables with `m_`.

Example:

```c
    public int32_t m_counter;
```

## Global variables

To know whether the variable is global or not, we start globals with `g_`.

Example:

```c
    int g_nplugins;
```

## Capitalization

The naming convention is camel-cased "Unix" style, i.e. always lower case. Words are separated by underscores.

Example:

```c
    int32_t g_global_bean_counter;
    int32_t count_beans();
```

and not,

```c
    int32_t GlobalBeanCounter;
    int32_t CountBeans();
```

## Packed Structures

Packed structures should use the GCC and MSVC-style supported `pragma`:

Example:

```c
    #pragma pack(push,1)
    struct frame_control
    {
        struct fields....
    };
    #pragma pack(pop)
```

## 64-bit constants

Put an `LL` at the end of your `64-bit` constants. Without the `LL`, some platform compilers try to interpret the constant on the right-hand side as a `long integer` instead of a `long long` and this could lead to an error at building time.

Example:

```c
    x=0X00FF00000000000LL
```

## Class Declaration

The class declaration follows the following sequence:

1. constructors and destructor
2. public functions
3. public data
4. private functions
5. private data
6. friend declarations

Example:

```cpp
    class foo
    {
    public:
      foo();
      ~foo();

      int32_t lonli();
      int32_t m_val;

    private:
      int32_t temustra();
      int32_t m_val2;
    };
```

## Struct guidelines

We think hiding the presence of a pointer makes the code unnecessarily ambiguous and more difficult.
Seeing a `*` in a variable declaration immediately identifies a pointer, which is easier to mentally keep track of!
Also, we think that defining the struct as a typedef makes forward declarations clunky and find using the C++ style when declaring our structs makes our lives easier.

Example:

```c
    //
    // Us human parsers find this confusing.
    //
    typedef struct _my_struct
    {
      u_int16 m_field;
    } my_struct,
    *p_my_struct;

    //
    // This is easier!
    //
    struct my_struct {
      u_int16 m_field;
    };
```

## Temporary variables

Since `j` is used less frequently in English prose than `a` or `i`, we find that these variables (in hierarchical order) are great for counters: `j`, `k`, `l`, `m`, `n`.

Example:

```c
    int32_t j,k;
    for(j = 0; j < 10; j++)
    {
      for(k = 0; k < 10; k++)
      {
        int32_t foo = j + k;
      }
    }
```

as opposed to:

```c
    int32_t i,counter;
    for(i = 0; i < 10; i++)
    {
      for(counter = 0; counter < 10; counter++)
      {
        int32_t foo = i + counter;
      }
    }
```

## Error management

Error management inside `libscap` is done through return values, since the scap library is written in C.
Error management in the rest of the user-level code base is done through `exceptions`. We know there's a lot of debate between return values and exceptions. We decided to pick the latter, so please stick with that.
