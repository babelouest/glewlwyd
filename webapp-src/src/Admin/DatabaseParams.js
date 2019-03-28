import React, { Component } from 'react';

class DatabaseParams extends Component {
  constructor(props) {
    super(props);
    
    if (!props.mod.parameters) {
      props.mod.parameters = {};
    }
    
    if (props.mod.parameters["use-glewlwyd-connection"] === undefined) {
      props.mod.parameters["use-glewlwyd-connection"] = true;
    }
    
    this.state = {
      mod: props.mod,
      role: props.role
    };
    
    this.toggleInternalConnection = this.toggleInternalConnection.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    if (!nextProps.mod.parameters) {
      nextProps.mod.parameters = {};
    }
    
    if (nextProps.mod && nextProps.mod.parameters && nextProps.mod.parameters["use-glewlwyd-connection"] === undefined) {
      nextProps.mod.parameters["use-glewlwyd-connection"] = true;
    }
    
    this.setState({
      mod: nextProps.mod,
      role: nextProps.role
    });
  }
  
  toggleInternalConnection(e) {
    var mod = this.state.mod;
    mod.parameters["use-glewlwyd-connection"] = !mod.parameters["use-glewlwyd-connection"];
    this.setState({mod: mod});
  }
  
  render() {
    var useInternalConnection = <div className="form-group">
      <label htmlFor="mod-database-use-internal-connection">{i18next.t("admin.mod-database-use-internal-connection")}</label>
      <input type="checkbox" className="form-control" id="mod-database-use-internal-connection" onChange={(e) => this.toggleInternalConnection(e)} checked={this.state.mod.parameters["use-glewlwyd-connection"]} />
    </div>
    if (this.state.role === "user") {
      return (
        useInternalConnection
      );
    } else if (this.state.role === "client") {
      return (
        useInternalConnection
      );
    } else {
      return ("");
    }
  }
}

export default DatabaseParams;
