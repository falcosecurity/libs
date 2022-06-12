# Coding style

## Introduction

This document introduces the coding style that will be applied in this repository.
This coding style involves all the following files: `.c`, `.h`, `.cpp`, `.cmake`, `CMakeLists.txt` and to enforce it we rely on two tools:

1. `clang-format` version `13.0.0`.
2. `cmake-format` version `0.6.13`.

> __Please note__: tools versions are important! Different versions will enforce slightly different changes on the code. For example `clang-format-14` will produce a slightly different code respect to `clang-format-13` always respecting the imposed style.

The coding style is expressed through the 2 configuration file that you find in this repo: `.clang-format`, `.cmake-format.json`.  

## Enforce the style locally

There are many ways to enforce the style locally, here we will describe two of them:

1. Use the repo `Makefile`.
2. Use `pre-commit` framework.

### Makefile

#### Step 1

In order to use the repo `Makefile`, you need to install on your local machine the two aforementioned tools: 

**clang-format v13.0.0**

One of the easiest way to install `clang-format` could be directly downloading its static binary from [here](https://github.com/muttleyxd/clang-tools-static-binaries).
There are other ways for example you can download the package for your distro or you can also build it from sources.

**cmake-format v0.6.13**
To install `cmake-format` you can follow the official documentation [here](https://cmake-format.readthedocs.io/en/latest/installation.html).

Please check the versions of the two tool with `clang-format --version` and `cmake-format --version`.

#### Step 2

Once you have installed the **right** versions of the 2 tools, you can simply type `make format-all` from the root directory of the project `/libs` to format all your code according with the coding style. Remember to do that before submitting a new patch upstream!

### Pre-commit framework (suggested if you don't have the 2 tools already installed on your machine)

`pre-commit` is a framework that allow you to automatically install diffent `git-hooks` that will run at every new commit. More precisely, if you use the `.pre-commit-config.yaml` in this file you will install 3 different hooks:

1. The `clang-format` hook: this is a `pre-commit` git hook that run `clang-format` on your staged changes.
2. The `cmake-format` hook: this is a `pre-commit` git hook that run `cmake-format` on your staged changes.
3. The `DCO signed-off` hook: this is a `pre-commit-msg` git hook that add the `DCO` on your commit if not present. This hook is not strictly related to the coding style so we will talk about it in a separate section: [Add DCO signed-off to your commits](#add-dco-signed-off-to-your-commits).

Now let's see what we need to use `pre-commit` framework.

#### Step 1

Install `pre-commit` framework following the [official documentation](https://pre-commit.com/#installation).

> __Please note__: you have to follow only the "Installation" section.

#### Step 2

Once you have installed `pre-commit`, you don't need to install anything else! This is the good point of using a framework like `pre-commit`, all the tools necessary to format your code will be directly managed by the framework. But in order to be ready you need to configure the git hooks in your local repo.

This simple command allow you to install the two `pre-commit` git hooks, `clang-format` and `cmake-format`.

```bash
pre-commit install --install-hooks --hook-type pre-commit --overwrite  
```

If you want to install also the `pre-commit-msg` git hook for the DCO you have to type the following command, but be sure to have configured all you need as said in the [dedicated section]((#add-dco-signed-off-to-your-commits))

```bash
pre-commit install --install-hooks --hook-type prepare-commit-msg --overwrite 
```

You have done, at every new commit, this hooks will check that your patch respects the coding style of this repo!

If you want to detach the git hooks, you can simply type:

```bash
pre-commit uninstall --hook-type prepare-commit-msg
pre-commit uninstall --hook-type pre-commit 
```

### Other solutions

Obviously, you can also install the 2 tools locally and enable some extension of your favourite editor (like `VScode`) to format your code every time you save your files. 

## Add DCO signed-off to your commits

Another requirement for contibuting to the `libs` repo, is applying the [DCO]() to every commit you want to push upstream.
Before doing this you have to configure your git user `name` and `email` if you haven't already done it. To check your actual `name` and `email` type:

```bash
git config --get user.name
git config --get user.email
```

If they are correct you have done, otherwise you have to set them:

```bash
git config user.name <full-name>
git config user.email <mail-used_with-GitHub-profile>
```
>__Please note__: If you have problems in doing this please read the full documentation [here]().

Now you are ready to sign your commits! Yuo have two main way to do this:

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

Here if have already added the hook in the [previous section](#step-2), you have to do nothing otherwise you have to simply install the DCO hook with:

```bash
pre-commit install --install-hooks --hook-type prepare-commit-msg --overwrite 
```

And you have done! Now you don't have to remember the `-s` option every time you commit something, the DCO hook will automatically add the DCO if you forget it.

## What our CI/CD does

Our `CI` will check both the coding style and the DCO on all your commits with 2 different jobs.
* The (name-of-the-job) job: will check the coding style according to the configuration files in this repo: `.clang-format` and `.cmake-format.json`. (Maybe can provide the diff as an artifcact to apply).
* The `dco` job: will check the DCO presence on all your commits.
