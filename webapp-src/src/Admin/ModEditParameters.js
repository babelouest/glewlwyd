import React, { Component } from 'react';

import MockParams from './MockParams';
import DatabaseParams from './DatabaseParams';
import LDAPParams from './LDAPParams';

class ModEditParameters extends Component {
  constructor(props) {
    super(props);

    this.state = {
      mod: props.mod,
      role: props.role,
      check: props.check
    };
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      mod: nextProps.mod,
      role: nextProps.role,
      check: nextProps.check
    });
  }
  
  render() {
    if (this.state.mod.module === "mock") {
      return <MockParams mod={this.state.mod} role={this.state.role} check={this.state.check} />
    } else if (this.state.mod.module === "database") {
      return <DatabaseParams mod={this.state.mod} role={this.state.role} check={this.state.check} />
    } else if (this.state.mod.module === "ldap") {
      return <LDAPParams mod={this.state.mod} role={this.state.role} check={this.state.check} />
    } else {
      return ("");
    }
  }
}

export default ModEditParameters;
