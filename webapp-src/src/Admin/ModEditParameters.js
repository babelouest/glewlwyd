import React, { Component } from 'react';

import MockParams from './MockParams';
import DatabaseParams from './DatabaseParams';
import LDAPParams from './LDAPParams';
import HTTPParams from './HTTPParams';
import EmailParams from './EmailParams';

class ModEditParameters extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      mod: props.mod,
      role: props.role,
      check: props.check
    };
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      mod: nextProps.mod,
      role: nextProps.role,
      check: nextProps.check
    });
  }
  
  render() {
    if (this.state.mod.module === "mock") {
      return <MockParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "database") {
      return <DatabaseParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "ldap") {
      return <LDAPParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "http") {
      return <HTTPParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else if (this.state.mod.module === "email") {
      return <EmailParams mod={this.state.mod} role={this.state.role} check={this.state.check} config={this.state.config} />
    } else {
      return ("");
    }
  }
}

export default ModEditParameters;
