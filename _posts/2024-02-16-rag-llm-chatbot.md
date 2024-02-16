---
layout: post
title: Using Retrieval Augmented Generation (RAG) for chatbots
date: 2024-02-16 13:00:00-0400
description: A simple example of how RAG can be used for a website's chatbot.
tags: RAG LLM NLP natural-language-processing retrieval-augmented-generation large-language-models chatbot python embeddings
categories: Artificial-Intelligence
thumbnail: /assets/img/2023-essentialeight.png #to do
related_posts: true
toc:
  sidebar: left
featured: false
---

# Introduction
This project leverages a Retrieval Augmented Generation (RAG) implementation to create an intelligent question-answering system. The project automates the collection of textual data from a specified website, processes this data to generate meaningful numerical vector representations (embeddings), and utilises these embeddings to provide contextually relevant answers to user queries in a chatbot from a Large Language Model.

You can find the code and a detailed overview in the <a href="https://github.com/emdeh/web-crawl-qna-blog-bot">Github repository</a>.

## Credits

It is based off **OpenAI's Web  Q&A with Embeddings tutorial**. Learn how to crawl your website and build a Q/A bot with the OpenAI API. You can find the full tutorial in the <a href="https://platform.openai.com/docs/tutorials/web-qa-embeddings">OpenAI documentation</a>.


# Overview of RAG

The diagram below briefly outlines how Retrieval Augmented Generation (RAG) implementations work. In short, they essentially *retrieve* additional context to *augment* the response *generated* by a LLM. 

The diagram below describes how embeddings are used to compare a prompt to a knowledge source in order to retrieve the most likely relevant context. The prompt and context is then provided to a LLM model (in this case gpt-3.5-turbo) to generate a contextually relevant response. 

<img src="/assets/img/2024-rag-chatbot/diagram.png" alt="diagram">

# Example implementation

1 : In the case of this particular implementation, the knowledge source is a blog. The knowledge is obtained by first extracting all the hyperlinks on the site, and discarding any that point to other domains. Each unique hyperlink is then visited and the content extracted into text files. The text files are then used to create a data frame. Each row in the data frame is tokenised, which  allows for analysing the length of documents, which is relevant for understanding the data's distribution and for optimising model input sizes. 

2 : After a bit more processing to create smaller chunks (if required), the embeddings are generated and saved; in this case, to a .csv file.

```bash
<SNIP>
https://emdeh.com/repositories
https://emdeh.com/news/announcement_7
https://emdeh.com/blog/2024/codify-walkthrough
Embeddings generated and saved to 'data/embeddings.csv'.
Preprocessing complete. Embeddings are ready.

# You can see the blog's links being iterated here.
```

3 - 5 :  When a user provides the prompt to the service it will also pass the prompt to the embeddings model to retrieve its vector.

<img src="/assets/img/2024-rag-chatbot/image-of-prompt.png" alt="image of prompt">

6: The service then compares the prompt's vector to the Vector DB (in this case, the .csv  file containing the blog's embeddings is loaded into another data frame). 

> *The comparision is done using Cosine function to calculate the distance between the question's embedding and each row's embedding in the data frame. Cosine distances is a measure used to determine the similarity between two vectors, with lower values indicating higher similarity.*

The service will then iterate over the data frame to accumulate the most similar text until it reaches a pre-defined token limit. This then forms the context for the original prompt.

7 - 9: The context, and original prompt, is then passed to the GPT model, which returns a generative completion. This completion is presented back to the end-user.

<img src="/assets/img/2024-rag-chatbot/image-of-completion.png" alt="image of completion">


# Code overview
 
 
## Data Collection and Preparation
`preprocess.py` crawls web pages within a specified domain and systematically navigates through the website, extracting text from each page it encounters. The collected text undergoes initial preprocessing to clean and organise the data, making it suitable for further analysis.

The script then employs OpenAI's API to generate embeddings for each piece of text. These embeddings capture the semantic essence of the text in a high-dimensional space, facilitating the identification of contextual similarities between different texts. The processed data, along with its embeddings, is saved for subsequent use, laying the groundwork for the question-answering capabilities of the system.

## Flask Application for Question Answering
With the data prepared, `app.py` serves as the interface between the user and the system's NLP engine. This script initiates a Flask web application, providing endpoints for users to submit their questions.

Upon receiving a query, the application leverages the previously generated embeddings to find the most relevant context within the collected data. It then formulates this context and the user's question as input for an OpenAI GPT model. 

The model, trained on vast amounts of text from the internet, generates an answer that reflects both the specific information contained in the crawled data and its understanding of the topic at large. The answer is then returned to the user through the web interface, completing the cycle of query and response.

## Integration and Workflow
The integration of `preprocess.py` and `app.py` creates a workflow that bridges web crawling and NLP-driven question answering. Initially, `preprocess.py` lays the foundation by collecting and preparing the data, which `app.py` subsequently utilises to offer real-time answers. This allows the system to provide answers that are not only contextually relevant but also deeply informed by the specific context of the targeted domain. Users interact with the system through a straightforward web interface, making complex NLP capabilities accessible to anyone with a question to ask.

## Use-cases
Together, these scripts leverage sophisticated machine learning capabilties to demonstrate  how existing data from websites can be harnessed to build powerful and interactive AI-driven ways to retrieve and discovery knowledge.

For example, the basic capabilities demonstrated in this project could be applied to create a contextually-aware chatbot on a website. 