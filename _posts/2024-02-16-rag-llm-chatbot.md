---
layout: post
title: Using Retrieval Augmented Generation (RAG) for chatbots
date: 2024-02-16 13:00:00-0400
description: A simple example of how RAG can be used for a website's chatbot.
tags: RAG LLM NLP natural-language-processing retrieval-augmented-generation large-language-models chatbot python embeddings
categories: Artificial-Intelligence
thumbnail: /assets/img/2024-rag-chatbot/rag-icon.webp
related_posts: true
toc:
  beginning: true
featured: false
---

# Introduction
This project leverages a Retrieval Augmented Generation (RAG) implementation to create an intelligent question-answering system for a website. The project automates the collection of contextual data from the site, processes this data with an embeddings model to generate vector representations, and utilises these vectors to provide relevant answers to user queries through a chatbot using a Language Model (LLM) to craft responses in a conservational tone.

You can find the code and a detailed overview in the <a href="https://github.com/emdeh/web-crawl-qna-blog-bot">Github repository</a>.

## What is Retrieval Augmented Generation (RAG)
Retrieval Augmented Generation (RAG) is a sophisticated approach that enhances the capabilities of generative models, particularly Large Language Models (LLMs), by integrating an additional information retrieval step into the response generation process. This method involves dynamically sourcing relevant external information to augment the input provided to the generative model, thereby enriching its responses with details and insights not contained within its pre-trained knowledge base. The retrieval of additional information is typically facilitated by embeddings and vector representations to identify content contextually similar to the user's prompt.

## What are Embeddings
Embeddings are a form of representation learning where words, sentences, or even entire documents are converted into real-valued vectors in a high-dimensional space. This process aims to capture the semantic meanings, relationships, and context of words or phrases, allowing machines to process natural language data more effectively. The vectors in the high-dimensional space represent the nuanced characteristics of the text, such as syntax, semantics, and usage patterns, in a form that can be quantitatively analysed. Each dimension could correspond to a latent feature that captures different aspects of the text's meaning, not directly interpretable by humans but discernible through computational methods. By mapping textual information to a geometric space, embeddings enable the measurement of conceptual similarity between pieces of text based on their positions and distances within this space, facilitating tasks like search, classification, and contextual understanding in natural language processing applications. In the context of Retrieval-Augmented Generation (RAG), embeddings represent the queries (prompts) and the potential knowledge sources in a format that a computer can understand and compare.

### Vector Representations
Vector representations are the outcome of converting text into embeddings, representing text as points or vectors in a multi-dimensional space. As described above, each dimension corresponds to a feature of the text, capturing various aspects of its meaning, context, or syntactical properties. Comparing vector representations involves calculating the similarity (often using cosine similarity or other metrics) between vectors to identify how closely related two pieces of text are. In RAG implementations that use embeddings, the vector representation of a user's prompt is compared to the vector representations of various knowledge sources to identify the most relevant context. This relevant context is then retrieved and used to augment the response generated by a language model, enhancing the LLM's ability to provide accurate and contextually enriched answers.

## Credits
This project was initially inspired by **OpenAI's Web  Q&A with Embeddings tutorial**. Learn how to crawl your website and build a Q/A bot with the OpenAI API. You can find the full tutorial in the <a href="https://platform.openai.com/docs/tutorials/web-qa-embeddings">OpenAI documentation</a>.


# Overview of a RAG implementation
The diagram below briefly outlines how a Retrieval Augmented Generation (RAG) architecture leverages embeddings. In short, additional context is *retrieved* by comparing the vectors of the prompt to the vectors of the knowledge source. The related textual data is then appended to the prompt to *augment* the response *generated* by the LLM.

<img src="/assets/img/2024-rag-chatbot/diagram.png" alt="diagram">

# Example implementation

**Point 1:** In the case of this particular implementation, the knowledge source is a blog. The knowledge is obtained by first extracting all the hyperlinks on the site and discarding any that point to other domains. Each unique hyperlink is then visited, and the content extracted into text files. The text files are then used to create a data frame. Each row in the data frame is tokenised to facilitate analysing the length of documents, which is relevant for understanding the data's distribution and optimising model input sizes. 

**Point 2:** After more processing to create smaller chunks (if required), the embeddings are generated and saved. In this case, to a `.csv` file.

```bash
<SNIP>
https://emdeh.com/repositories
https://emdeh.com/news/announcement_7
https://emdeh.com/blog/2024/codify-walkthrough
Embeddings generated and saved to 'data/embeddings.csv'.
Preprocessing complete. Embeddings are ready.

# You can see the blog's links being iterated here.
```

**Points 3 - 5:** When a user provides the prompt to the service, the embeddings model will generate its vector representation.

<img src="/assets/img/2024-rag-chatbot/image-of-prompt.png" alt="image of prompt">

**Point 6:** The service then compares the prompt's vector to the Vector DB (in this case, the `.csv` file containing the blog's vector representations is loaded into another data frame). 

> *The comparision is done using Cosine function to calculate the distance between the question's embedding and each row's embedding in the data frame. Cosine distances is a measure used to determine the similarity between two vectors, with lower values indicating higher similarity.*

The service will then iterate over the data frame to accumulate the most similar text until it reaches a pre-defined token limit. This then forms the context for the original prompt.

**Points 7 - 9:** The context and original prompt are now passed to the GPT model, which returns a generative completion. This completion is presented back to the end-user.

<img src="/assets/img/2024-rag-chatbot/image-of-completion.png" alt="image of completion">


# Code overview
 
 
## Data Collection and Preparation
`preprocess.py` crawls web pages within a specified domain and systematically navigates through the website, extracting text from each page it encounters. The collected text undergoes initial preprocessing to clean and organise the data, making it suitable for further analysis.

The script then employs OpenAI's API to generate embeddings for each piece of text. These embeddings capture the semantic essence of the text in a high-dimensional space, facilitating the identification of contextual similarities between different texts. The processed data and its embeddings are saved for subsequent use, laying the groundwork for the system's question-answering capabilities.

## Flask Application for Question Answering
With the data prepared, `app.py` serves as the interface between the user and the system's NLP engine. This script initiates a Flask web application, providing endpoints for users to submit their questions.

Upon receiving a query, the application leverages the previously generated embeddings to find the most relevant context within the collected data. It then formulates this context and the user's question as input for an OpenAI GPT model. The model, trained on vast amounts of text from the internet, generates an answer that reflects the specific information in the crawled data and its understanding of the topic at large. The answer is then returned to the user through the web interface, completing the cycle of query and response.

## Integration and Workflow
Integrating `preprocess.py` and `app.py` creates a workflow that bridges web crawling and NLP-driven question-answering. Initially, `preprocess.py` lays the foundation by collecting and preparing the data, which `app.py` subsequently utilises to offer real-time answers. This allows the system to provide contextually relevant answers informed by the specific context. Users interact with the system through a straightforward web interface, making complex NLP capabilities accessible to anyone with a question to ask.

## Use-cases
Together, these scripts leverage sophisticated machine learning capabilities to demonstrate how existing data from websites can be harnessed to build robust and interactive AI-driven ways to retrieve and discover knowledge.

For example, the basic capabilities demonstrated in this project could be applied to create a contextually-aware chatbot on a website. 