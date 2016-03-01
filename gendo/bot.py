#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from collections import namedtuple
import json
import logging
import inspect
import datetime
import os
import sys
import time

from slackclient import SlackClient
from .scheduler import Task
from . import __version__
import six
import yaml

log = logging.getLogger(__name__)
HERE = os.path.dirname(os.path.abspath(__file__))

Listener = namedtuple('Listener', ('rule', 'view_func', 'func_args', 'decorator_options'))


class Gendo(object):
    def __init__(self, slack_token=None, settings=None):
        self.settings = settings or {}
        self.listeners = []
        self.handlers = {}
        self.scheduled_tasks = []
        self.client = SlackClient(
            slack_token or self.settings.get('gendo', {}).get('auth_token'))
        self.sleep = self.settings.get('gendo', {}).get('sleep') or 0.5
        self._events = self._get_valid_events()

    @classmethod
    def config_from_yaml(cls, path_to_yaml):
        with open(path_to_yaml, 'r') as ymlfile:
            settings = yaml.load(ymlfile)
            log.info("settings from %s loaded successfully", path_to_yaml)
            return cls(settings=settings)

    @property
    def id(self):
        """Get id of the bot."""

        if not hasattr(self, '_id',):
            self._id = self.client.server.login_data['self']['id']
        return self._id

    @property
    def username(self):
        """Get username of the bot."""

        if not hasattr(self, '_username',):
            self._username = self.client.server.username
        return self._username

    def _verify_rule(self, supplied_rule):
        """Rules must be callable with (user, message) in the signature.
        Strings are automatically converted to callables that match.

        :returns: Callable rule function with user, message as signature.
        :raises ValueError: If `supplied_rule` is neither a string nor a
                            callable with the appropriate signature.
        """

        # If string, make a simple match callable
        if isinstance(supplied_rule, six.string_types):
            return lambda user, channel, message: supplied_rule in message.lower()

        if not six.callable(supplied_rule):
            raise ValueError('Bot rules must be callable or strings')

        expected = ('user', 'channel', 'message')
        signature = tuple(inspect.getargspec(supplied_rule).args)
        try:
            # Support class- and instance-methods where first arg is
            # something like `self` or `cls`.
            assert len(signature) in (3, 4)
            assert expected == signature or expected == signature[-3:]
        except AssertionError:
            msg = 'Rule signuture must have only 3 arguments: user, channel, message'
            raise ValueError(msg)

        return supplied_rule

    def validate_event_name(self, event_name):
        if event_name not in self._events:
            raise ValueError('{} is not a valid event name.'.format(event_name))

    def listen_for(self, rule, **options):
        """Decorator for adding a Rule. See guidelines for rules.
        """
        rule = self._verify_rule(rule)
        def decorator(f):
            def wrapped(**kwargs):
                self.add_listener(rule, f, kwargs, options)
                return f
            return wrapped()
        return decorator

    def handle_event(self, event_name, **options):
        """Decorator for handling an event.

        See https://api.slack.com/events for list of event names.

        """
        self.validate_event_name(event_name)
        def decorator(f):
            def wrapped(**kwargs):
                self.add_handler(event_name, f, kwargs, options)
                return f
            return wrapped()
        return decorator

    def cron(self, schedule, **options):
        def decorator(f):
            self.add_cron(schedule, f, **options)
            return f
        return decorator

    def run(self):
        running = True
        if self.client.rtm_connect():
            while running:
                time.sleep(self.sleep)
                now = datetime.datetime.now()
                try:
                    data = self.client.rtm_read()
                    if data and data[0].get('type') == 'message':
                        log.debug(data)
                        user = data[0].get('user')
                        message = data[0].get('text')
                        channel = data[0].get('channel')
                        self.respond(user, message, channel)

                    elif data:
                        event_name = data[0].get('type')
                        self.handle(event_name, dict(data[0]))

                    for idx, task in enumerate(self.scheduled_tasks):
                        if now > task.next_run:
                            t = self.scheduled_tasks.pop(idx)
                            t.run()
                            self.add_cron(t.schedule, t.fn, **t.options)
                except (KeyboardInterrupt, SystemExit):
                    log.info("attempting graceful shutdown...")
                    running = False
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)

    def respond(self, user, message, channel):
        if not message:
            return

        elif message == 'gendo version':
            self.speak("Gendo v{0}".format(__version__), channel)
            return

        for rule, view_func, options, decorator_options in self.listeners:
            ignore_channel_names = decorator_options.get('ignore_channels', [])
            ignore_channels = {
                self.get_channel_by_name(name) for name in ignore_channel_names
            }
            if channel in ignore_channels or user == self.id:
                continue

            elif rule(user, channel, message):
                response = view_func(user, channel, message, **options)
                if not response:
                    continue
                if '{user.username}' in response:
                    response = response.replace('{user.username}', self.get_user_name(user))
                if '{channel.name}' in response:
                    response = response.replace('{channel.name}', '<#{}>'.format(channel))
                target_channel = decorator_options.get('target_channel')
                if target_channel is not None:
                    channel = self.get_channel_by_name(target_channel)
                log.debug('target channel is {}'.format(channel))
                self.speak(response, channel)

    def add_listener(self, rule, view_func=None, func_args=None,
                     decorator_options=None):
        """Adds a listener to the listeners container; verifies that
        `rule` and `view_func` are callable.

        :raises TypeError: if rule is not callable.
        :raises TypeError: if view_func is not callable
        """
        if not six.callable(rule):
            raise TypeError('rule should be callable')
        if not six.callable(view_func):
            raise TypeError('view_func should be callable')
        self.listeners.append((rule, view_func, func_args, decorator_options))

    def add_handler(self, event_name, f=None, args=None, decorator_options=None):
        # FIXME: What?
        handlers = self.handlers.setdefault(event_name, [])
        handlers.append((f, args, decorator_options))

    def handle(self, event_name, data):
        handlers = self.handlers.get(event_name, [])
        for function, args, decorator_options in handlers:
            user, channel, response = function(data, **args)
            if not response:
                continue

            if '{user.username}' in response:
                response = response.replace('{user.username}', self.get_user_name(user))

            if '{channel.name}' in response:
                response = response.replace('{channel.name}', '<#{}>'.format(channel))

            target_channel = decorator_options.get('target_channel')
            if target_channel is not None:
                channel = self.get_channel_by_name(target_channel)
                log.debug('target channel is {}'.format(channel))

            self.speak(response, channel)

    def add_cron(self, schedule, f, **options):
        self.scheduled_tasks.append(Task(schedule, f, **options))

    def speak(self, message, channel):
        res = self.client.api_call("chat.postMessage", as_user="true:",
                             channel=channel, text=message)
        log.debug(res.decode('utf-8'))

    def get_user_info(self, user_id):
        user = self.client.api_call('users.info', user=user_id).decode('utf-8')
        return json.loads(user)

    def get_user_name(self, user_id):
        user = self.get_user_info(user_id)
        return user.get('user', {}).get('name')

    def get_channel_by_name(self, channel_name):
        """ Returns channel id by its name """
        channel = self.client.server.channels.find(channel_name)
        return channel.id

    def _get_valid_events(self):
        with open(os.path.join(HERE, 'events.json')) as f:
            return set(json.load(f))
