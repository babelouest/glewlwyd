import React, { Component } from 'react';
import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';

class MockPluginsParams extends Component {
  constructor(props) {
    super(props);

    this.state = {
      mod: props.mod,
      role: props.role,
      check: props.check,
      hasError: false
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
    
    this.checkParameters = this.checkParameters.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      mod: nextProps.mod,
      role: nextProps.role,
      check: nextProps.check,
      hasError: false
    }, () => {
      if (this.state.check) {
        this.checkParameters();
      }
    });
  }
  
  checkParameters() {
    messageDispatcher.sendMessage('ModPlugin', {type: "modValid"});
  }
  
  render() {
    return ("");
  }
}

export default MockPluginsParams;
