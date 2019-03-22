import React, { Component } from 'react';

class ModEditParameters extends Component {
  constructor(props) {
    super(props);

    this.state = {
      mod: props.mod,
      changeParameters: props.changeParameters
    };
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      mod: nextProps.mod,
      changeParameters: nextProps.changeParameters
    });
  }
  
  render() {
    return ("");
  }
}

export default ModEditParameters;
