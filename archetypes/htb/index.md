---
title: {{ replace .Name "-" " " | title }}
date: {{ .Date | time.Format ":date_short" }}
summary: "Writeup for the {{ title .Name }} lab machine on HackTheBox"
draft: true
tags: [Hacking]
categories: [HackTheBox]
cover:
    image: "images/cover.png" # image path/url
    alt: {{ replace .Name "-" " " | title }} # alt text
    caption: "" # display caption under cover
    relative: true # when using page bundles set this to true
---

# Introduction

## Enumeration

### Nmap

## user.txt

## root.txt
