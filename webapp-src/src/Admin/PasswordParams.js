import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class PasswordParams extends Component {
  constructor(props) {
    super(props);
    
    if (!props.mod) {
      props.mod = {parameters: {}};
    }
    
    this.state = {
      config: props.config,
      mod: props.mod,
      role: props.role,
      check: props.check,
      hasError: false,
      errorList: {}
    };
    
    if (this.state.check) {
      this.checkParameters();
    }
  }
  
  componentWillReceiveProps(nextProps) {
    
    if (!nextProps.mod) {
      nextProps.mod = {parameters: {}};
    }
    
    this.setState({
      config: nextProps.config,
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
    var errorList = {}, hasError = false;
    if (!hasError) {
      this.setState({errorList: {}}, () => {
        messageDispatcher.sendMessage('ModEdit', {type: "modValid"});
      });
    } else {
      this.setState({errorList: errorList});
    }
  }
  
  render() {
    return (
      <div>
      </div>
    );
  }
}

export default PasswordParams;
